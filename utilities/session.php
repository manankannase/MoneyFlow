<?php
/**
 * Session Management
 *
 * Custom DB-backed session using 256-bit cryptographically secure tokens.
 * Tokens are stored as SHA-256 hashes in the database (never raw).
 * Sessions are bound to IP address and User-Agent hash.
 */

require_once __DIR__ . '/../settings/db_config.php';

define('SESSION_COOKIE_NAME', 'mf_session');
define('SESSION_LIFETIME_SECONDS', 86400);  // 24 hours

/**
 * Create a new session for a member after successful login.
 *
 * @return string The raw session token to set as a cookie.
 */
function createSession(int $memberId): string {
    $rawToken   = bin2hex(random_bytes(32));   // 256-bit token
    $tokenHash  = hash('sha256', $rawToken);
    $csrfToken  = bin2hex(random_bytes(32));
    $agentHash  = hash('sha256', $_SERVER['HTTP_USER_AGENT'] ?? '');
    $ipAddress  = getClientIp();
    $expiresAt  = date('Y-m-d H:i:s', time() + SESSION_LIFETIME_SECONDS);

    $pdo  = getDbConnection();
    $stmt = $pdo->prepare(
        'INSERT INTO member_sessions
             (member_id, token_hash, csrf_token, agent_hash, ip_address, expires_at)
         VALUES (:member_id, :token_hash, :csrf_token, :agent_hash, :ip_address, :expires_at)'
    );
    $stmt->execute([
        ':member_id'  => $memberId,
        ':token_hash' => $tokenHash,
        ':csrf_token' => $csrfToken,
        ':agent_hash' => $agentHash,
        ':ip_address' => $ipAddress,
        ':expires_at' => $expiresAt,
    ]);

    setSessionCookie($rawToken);
    return $rawToken;
}

/**
 * Validate the current session from the request cookie.
 *
 * Returns the session row (including csrf_token and member_id) on success,
 * or null if the session is invalid, expired, or bound to a different client.
 *
 * @return array|null
 */
function validateSession(): ?array {
    $rawToken = $_COOKIE[SESSION_COOKIE_NAME] ?? null;
    if (empty($rawToken)) {
        return null;
    }

    $tokenHash = hash('sha256', $rawToken);
    $agentHash = hash('sha256', $_SERVER['HTTP_USER_AGENT'] ?? '');
    $ipAddress = getClientIp();

    try {
        $pdo  = getDbConnection();
        $stmt = $pdo->prepare(
            'SELECT s.id, s.member_id, s.csrf_token, s.agent_hash, s.ip_address, s.expires_at,
                    m.account_name, m.email_address, m.account_balance, m.member_bio, m.profile_photo
             FROM member_sessions s
             JOIN members m ON m.id = s.member_id
             WHERE s.token_hash = :token_hash
               AND s.expires_at > NOW()
             LIMIT 1'
        );
        $stmt->execute([':token_hash' => $tokenHash]);
        $session = $stmt->fetch();

        if (!$session) {
            return null;
        }

        // Bind session to IP and User-Agent
        if (!hash_equals($session['agent_hash'], $agentHash)
            || $session['ip_address'] !== $ipAddress
        ) {
            destroySession($rawToken);
            return null;
        }

        return $session;
    } catch (PDOException $e) {
        error_log('MoneyFlow validateSession error: ' . $e->getMessage());
        return null;
    }
}

/**
 * Destroy the session identified by the raw token cookie.
 */
function destroySession(?string $rawToken = null): void {
    if ($rawToken === null) {
        $rawToken = $_COOKIE[SESSION_COOKIE_NAME] ?? null;
    }

    if (!empty($rawToken)) {
        $tokenHash = hash('sha256', $rawToken);
        try {
            $pdo  = getDbConnection();
            $stmt = $pdo->prepare('DELETE FROM member_sessions WHERE token_hash = :token_hash');
            $stmt->execute([':token_hash' => $tokenHash]);
        } catch (PDOException $e) {
            error_log('MoneyFlow destroySession error: ' . $e->getMessage());
        }
    }

    // Expire the cookie — use same secure flag as creation
    $isSecure = (getenv('APP_ENV') === 'production')
             || (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
             || (int) ($_SERVER['SERVER_PORT'] ?? 80) === 443;

    setcookie(SESSION_COOKIE_NAME, '', [
        'expires'  => time() - 3600,
        'path'     => '/',
        'httponly' => true,
        'samesite' => 'Strict',
        'secure'   => $isSecure,
    ]);
}

/**
 * Validate a CSRF token for a POST request.
 */
function validateCsrfToken(string $submittedToken, string $sessionCsrfToken): bool {
    return hash_equals($sessionCsrfToken, $submittedToken);
}

/**
 * Get the real client IP, accounting for common proxies.
 */
function getClientIp(): string {
    foreach (['HTTP_X_FORWARDED_FOR', 'HTTP_CLIENT_IP', 'REMOTE_ADDR'] as $key) {
        if (!empty($_SERVER[$key])) {
            // X-Forwarded-For can be a comma-separated list; take the first
            $ip = trim(explode(',', $_SERVER[$key])[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }
    }
    return '0.0.0.0';
}

/**
 * Set the session cookie with secure attributes.
 * The 'secure' flag is enabled when the app is running behind HTTPS.
 */
function setSessionCookie(string $rawToken): void {
    $isSecure = (getenv('APP_ENV') === 'production')
             || (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
             || (int) ($_SERVER['SERVER_PORT'] ?? 80) === 443;

    setcookie(SESSION_COOKIE_NAME, $rawToken, [
        'expires'  => time() + SESSION_LIFETIME_SECONDS,
        'path'     => '/',
        'httponly' => true,
        'samesite' => 'Strict',
        'secure'   => $isSecure,
    ]);
}
