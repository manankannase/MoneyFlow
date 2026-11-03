<?php
/**
 * HTTP Security Headers
 *
 * Sets comprehensive security headers to protect against common web vulnerabilities.
 * Should be called at the very beginning of every page before any output.
 */

/**
 * Get HMAC secret key from environment or use a fallback.
 * CRITICAL: In production, this should come from environment variables, not hardcoded.
 *
 * @return string HMAC secret key
 */
function getHMACSecret(): string {
    // FIX V3: No hardcoded fallback. If the env var is missing or too short,
    // the server refuses to start rather than silently use a known-to-opponents key.
    // Opponents receive your source code in the course zip — any fallback is public.
    $secret = getenv('HMAC_SECRET');
    if ($secret === false || strlen($secret) < 32) {
        error_log('FATAL: HMAC_SECRET env var is not set or is shorter than 32 chars.');
        http_response_code(500);
        exit('Server configuration error. Contact administrator.');
    }
    return $secret;
}

/**
 * Retrieve AES-256 transfer key from environment.
 * Key must be exactly 64 hex characters (32 bytes).
 *
 * @return string Raw 32-byte binary key
 */
function getAESTransferKey(): string {
    $hex = getenv('AES_TRANSFER_KEY');
    if ($hex === false || strlen($hex) !== 64 || !ctype_xdigit($hex)) {
        error_log('FATAL: AES_TRANSFER_KEY env var is missing or not a valid 64-char hex string.');
        http_response_code(500);
        exit('Server configuration error. Contact administrator.');
    }
    return hex2bin($hex);
}

/**
 * Encrypt transfer details into an AES-256-GCM authenticated token.
 *
 * The token contains recipient_id, amount, sender_id, nonce, and timestamp —
 * all server-chosen values that the client cannot read or alter.
 * GCM mode provides both confidentiality AND authentication: any tampering
 * with the ciphertext causes decryption to return false.
 *
 * Token format (base64-encoded): IV (12 bytes) || Tag (16 bytes) || Ciphertext
 *
 * @param int    $recipientId Recipient member ID
 * @param float  $amount      Transfer amount
 * @param int    $senderId    Sender member ID (from session — prevents token reuse across accounts)
 * @param string $nonce       One-time random nonce (also stored in session for anti-replay)
 * @param int    $timestamp   Unix timestamp (for expiry check on decryption)
 * @return string Base64-encoded encrypted token
 */
function encryptTransferToken(int $recipientId, float $amount, int $senderId, string $nonce, int $timestamp): string {
    $key = getAESTransferKey();
    $iv  = random_bytes(12); // 96-bit IV — recommended for AES-GCM

    $payload = json_encode([
        'recipient_id' => $recipientId,
        'amount'       => number_format($amount, 2, '.', ''),
        'sender_id'    => $senderId,
        'nonce'        => $nonce,
        'timestamp'    => $timestamp,
    ]);

    $tag        = '';
    $ciphertext = openssl_encrypt(
        $payload,
        'aes-256-gcm',
        $key,
        OPENSSL_RAW_DATA,
        $iv,
        $tag,
        '',
        16  // 128-bit authentication tag
    );

    if ($ciphertext === false) {
        error_log('AES-256-GCM encryption failed: ' . openssl_error_string());
        throw new RuntimeException('Token generation failed.');
    }

    // Pack IV + Tag + Ciphertext and base64-encode for safe HTTP transport
    return base64_encode($iv . $tag . $ciphertext);
}

/**
 * Decrypt and authenticate an AES-256-GCM transfer token.
 *
 * Returns null on any failure — tampered ciphertext, wrong key, bad format.
 * The caller must still validate sender_id, timestamp, and nonce.
 *
 * @param string $tokenB64 Base64-encoded token from client
 * @return array|null Decrypted payload or null if invalid/tampered
 */
function decryptTransferToken(string $tokenB64): ?array {
    $raw = base64_decode($tokenB64, true);
    // Minimum: 12 (IV) + 16 (tag) + 1 (ciphertext) = 29 bytes
    if ($raw === false || strlen($raw) < 29) {
        return null;
    }

    $key        = getAESTransferKey();
    $iv         = substr($raw, 0, 12);
    $tag        = substr($raw, 12, 16);
    $ciphertext = substr($raw, 28);

    // GCM decryption verifies the authentication tag — returns false if tampered
    $plaintext = openssl_decrypt(
        $ciphertext,
        'aes-256-gcm',
        $key,
        OPENSSL_RAW_DATA,
        $iv,
        $tag
    );

    if ($plaintext === false) {
        return null; // Ciphertext was tampered or key is wrong
    }

    $payload = json_decode($plaintext, true);
    if (!is_array($payload)) {
        return null;
    }

    // Ensure all required fields are present
    foreach (['recipient_id', 'amount', 'sender_id', 'nonce', 'timestamp'] as $field) {
        if (!isset($payload[$field])) {
            return null;
        }
    }

    return $payload;
}

/**
 * Apply comprehensive security headers to response.
 * Must be called before any output is sent.
 */
function applySecurityHeaders(): void {
    // Prevent browsers from guessing MIME types
    header('X-Content-Type-Options: nosniff');

    // Prevent clickjacking attacks
    header('X-Frame-Options: DENY');

    // Enable XSS filter in legacy browsers
    header('X-XSS-Protection: 1; mode=block');

    // Referrer policy: limit referrer information
    header('Referrer-Policy: strict-origin-when-cross-origin');

    // Content Security Policy: restrict resource loading
    header(
        "Content-Security-Policy: default-src 'self'; " .
        "script-src 'self'; " .
        "style-src 'self'; " .
        // FIX #22: Removed data: from img-src — profile photos are real file URLs,
        // not data: URIs. data: in img-src enables CSS-based data exfiltration via
        // background-image: url('data:...') if a CSS injection point is ever found.
        "img-src 'self'; " .
        "font-src 'self'; " .
        "connect-src 'self'; " .
        "frame-ancestors 'none'; " .
        "form-action 'self'; " .
        "base-uri 'self'; " .
        "upgrade-insecure-requests; "
    );

    // Restrict browser features
    header('Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()');

    // Cache control for sensitive pages
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0, private');
    header('Pragma: no-cache');
    header('Expires: 0');

    // HSTS header — instructs browsers to only connect via HTTPS
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');

    // Start response integrity tracking (HMAC of response body)
    startResponseIntegrity();
}

/**
 * Start response integrity tracking via output buffering.
 * Call this at the beginning of a page (after applySecurityHeaders).
 * The buffer callback computes an HMAC-SHA256 over the entire response body
 * and adds an X-Response-Integrity header, allowing detection of response
 * tampering in transit.
 */
function startResponseIntegrity(): void {
    ob_start(function(string $buffer, int $phase): string {
        if (($phase & PHP_OUTPUT_HANDLER_FINAL) || ($phase & PHP_OUTPUT_HANDLER_END)) {
            $secret = getenv('HMAC_SECRET');
            if ($secret !== false && strlen($secret) >= 32) {
                $hash = hash_hmac('sha256', $buffer, $secret);
                header('X-Response-Integrity: sha256=' . $hash);
            }
        }
        return $buffer;
    });
}
?>
