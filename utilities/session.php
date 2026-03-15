<?php
/**
 * Session Management System
 *
 * Advanced security features:
 * - Session tokens generated using cryptographically secure random_bytes (32 bytes = 256 bits)
 * - Only SHA-256 hash of tokens stored in database (prevents exposure if DB compromised)
 * - Sessions bound to client IP address and User-Agent hash (prevents session hijacking)
 * - Cookies use HttpOnly, SameSite=Strict, and Secure flags
 * - Session timeout: 30 minutes of inactivity
 * - Session tokens regenerated on authentication to prevent fixation attacks
 */

require_once __DIR__ . '/../settings/db_config.php';

// Session timeout in seconds (sliding inactivity window)
define('SESSION_TIMEOUT', 1800);
// Absolute session lifetime — session is force-expired after this regardless of activity.
// Prevents a stolen token from staying valid forever via constant keep-alive requests.
define('SESSION_ABSOLUTE_LIFETIME', 18000); // 5 hours
define('SESSION_COOKIE_LABEL', 'MONEYFLOW_AUTH');

/**
 * Generate cryptographically secure random token.
 *
 * @return string Random 64-character hex token
 */
function generateSecureToken(): string {
    return bin2hex(random_bytes(32));
}

/**
 * Create SHA-256 hash of a token for secure storage.
 *
 * @param string $rawToken Unhashed token
 * @return string SHA-256 hash hex digest
 */
function hashTokenValue(string $rawToken): string {
    return hash('sha256', $rawToken);
}

/**
 * Get User-Agent header hash for session binding.
 * Prevents session use from different browsers/devices.
 *
 * @return string SHA-256 hash of User-Agent string
 */
function computeUserAgentFingerprint(): string {
    $agentString = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown_agent';
    return hash('sha256', $agentString);
}

/**
 * Get client's IP address.
 * 
 * NOTE: X-Forwarded-For header can be spoofed. We use REMOTE_ADDR which comes from
 * the TCP connection and cannot be spoofed at network level.
 *
 * @return string Client IP address
 */
function retrieveClientIPAddress(): string {
    return $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
}

/**
 * Create a new session for an authenticated member.
 *
 * @param int $memberID The authenticated member's ID
 * @return string Raw session token (to send as cookie)
 */
function initializeNewSession(int $memberID): string {
    $dbConn = getPDOConnection();

    // Regenerate PHPSESSID on login to prevent session fixation attacks.
    // The native PHP session (PHPSESSID) holds transfer nonces; if an attacker
    // fixed it before login they would retain access after authentication.
    if (session_status() === PHP_SESSION_NONE) {
        session_start(['cookie_httponly' => true, 'cookie_samesite' => 'Strict', 'cookie_secure' => true]);
    }
    session_regenerate_id(true);

    // Generate cryptographically secure token
    $sessionToken = generateSecureToken();
    $tokenHash = hashTokenValue($sessionToken);

    // Generate CSRF protection token
    $csrfToken = generateSecureToken();

    // Compute session fingerprint
    $agentHash = computeUserAgentFingerprint();
    $ipAddress = retrieveClientIPAddress();
    $expirationTime = time() + SESSION_TIMEOUT;

    // Invalidate all existing sessions for this member before creating a new one.
    // If an attacker stole a session token, they lose access the moment the victim
    // logs in again — not just when the victim changes their password (V8).
    $clearOldSessions = $dbConn->prepare(
        'DELETE FROM member_sessions WHERE member_id = :member_id'
    );
    $clearOldSessions->execute([':member_id' => $memberID]);

    // Store hashed token and CSRF token in database
    $insertQuery = $dbConn->prepare(
        'INSERT INTO member_sessions
         (member_id, token_hash, csrf_token, agent_hash, ip_address, expires_at)
         VALUES (:member_id, :token_hash, :csrf_token, :agent_hash, :ip_address, :expires_at)'
    );

    $insertQuery->execute([
        ':member_id'   => $memberID,
        ':token_hash'  => $tokenHash,
        ':csrf_token'  => $csrfToken,
        ':agent_hash'  => $agentHash,
        ':ip_address'  => $ipAddress,
        ':expires_at'  => date('Y-m-d H:i:s', $expirationTime),
    ]);

    // Set secure session cookie
    $cookieOptions = [
        'expires'  => $expirationTime,
        'path'     => '/',
        'domain'   => '',
        'secure'   => true,
        'httponly' => true,
        'samesite' => 'Strict',
    ];

    setcookie(SESSION_COOKIE_LABEL, $sessionToken, $cookieOptions);

    return $sessionToken;
}

/**
 * Validate current session.
 *
 * @return array|null Session data if valid, null if no valid session
 */
function validateActiveSession(): ?array {
    // Ensure PHP's native session is started so $_SESSION is available for
    // storing transfer nonces, timestamps, and other request-scoped data.
    if (session_status() === PHP_SESSION_NONE) {
        session_start(['cookie_httponly' => true, 'cookie_samesite' => 'Strict', 'cookie_secure' => true]);
    }

    if (!isset($_COOKIE[SESSION_COOKIE_LABEL])) {
        return null;
    }

    $sessionToken = $_COOKIE[SESSION_COOKIE_LABEL];
    if (!is_string($sessionToken) || strlen($sessionToken) !== 64) {
        return null;
    }

    $tokenHash = hashTokenValue($sessionToken);
    $agentHash = computeUserAgentFingerprint();
    $ipAddress = retrieveClientIPAddress();

    $dbConn = getPDOConnection();
    
    $fetchQuery = $dbConn->prepare(
        'SELECT member_id, csrf_token, agent_hash, ip_address, expires_at, created_at
         FROM member_sessions
         WHERE token_hash = :token_hash LIMIT 1'
    );
    
    $fetchQuery->execute([':token_hash' => $tokenHash]);
    $sessionRecord = $fetchQuery->fetch();

    if (!$sessionRecord) {
        return null;
    }

    // Check sliding inactivity expiration
    $expiresAt = strtotime($sessionRecord['expires_at']);
    if ($expiresAt < time()) {
        $deleteQuery = $dbConn->prepare('DELETE FROM member_sessions WHERE token_hash = :token_hash');
        $deleteQuery->execute([':token_hash' => $tokenHash]);
        return null;
    }

    // Check absolute session lifetime — force-expire even if kept active.
    // A stolen token cannot live beyond SESSION_ABSOLUTE_LIFETIME from creation.
    $absoluteExpiry = strtotime($sessionRecord['created_at']) + SESSION_ABSOLUTE_LIFETIME;
    if ($absoluteExpiry < time()) {
        $deleteQuery = $dbConn->prepare('DELETE FROM member_sessions WHERE token_hash = :token_hash');
        $deleteQuery->execute([':token_hash' => $tokenHash]);
        return null;
    }

    // Verify IP and User-Agent haven't changed (session hijacking protection)
    if ($sessionRecord['agent_hash'] !== $agentHash || $sessionRecord['ip_address'] !== $ipAddress) {
        error_log("Session hijacking attempt detected: IP or User-Agent mismatch");
        return null;
    }

    // Extend the sliding inactivity window on every valid request.
    // Without this UPDATE the 30-minute window would be fixed from login,
    // not a true inactivity timeout.
    $newExpiry = date('Y-m-d H:i:s', time() + SESSION_TIMEOUT);
    $refreshQuery = $dbConn->prepare(
        'UPDATE member_sessions SET expires_at = :expires_at WHERE token_hash = :token_hash'
    );
    $refreshQuery->execute([':expires_at' => $newExpiry, ':token_hash' => $tokenHash]);

    // Fetch member details
    $memberQuery = $dbConn->prepare(
        'SELECT id, account_name, email_address FROM members WHERE id = :id LIMIT 1'
    );
    $memberQuery->execute([':id' => $sessionRecord['member_id']]);
    $memberData = $memberQuery->fetch();

    if (!$memberData) {
        return null;
    }

    return [
        'member_id'   => (int) $memberData['id'],
        'account_name' => $memberData['account_name'],
        'email_address' => $memberData['email_address'],
        'csrf_token'   => $sessionRecord['csrf_token'],
    ];
}

/**
 * Terminate current session.
 */
function destroyActiveSession(): void {
    if (!isset($_COOKIE[SESSION_COOKIE_LABEL])) {
        return;
    }

    $sessionToken = $_COOKIE[SESSION_COOKIE_LABEL];
    $tokenHash = hashTokenValue($sessionToken);

    try {
        $dbConn = getPDOConnection();
        $deleteQuery = $dbConn->prepare('DELETE FROM member_sessions WHERE token_hash = :token_hash');
        $deleteQuery->execute([':token_hash' => $tokenHash]);
    } catch (PDOException $e) {
        error_log('Session deletion failed: ' . $e->getMessage());
    }

    // Clear cookie — use same flags as creation so browsers match and delete it
    setcookie(SESSION_COOKIE_LABEL, '', [
        'expires'  => time() - 3600,
        'path'     => '/',
        'domain'   => '',
        'secure'   => true,
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
}

/**
 * Get CSRF token for current session.
 * If no session, generates a temporary token.
 *
 * @return string CSRF token
 */
function produceCSRFToken(): string {
    $session = validateActiveSession();
    if ($session) {
        return $session['csrf_token'];
    }

    // Generate temporary token if not in session
    if (!isset($_SESSION['temp_csrf_token'])) {
        if (session_status() === PHP_SESSION_NONE) {
            session_start(['cookie_httponly' => true, 'cookie_samesite' => 'Strict', 'cookie_secure' => true]);
        }
        $_SESSION['temp_csrf_token'] = generateSecureToken();
    }

    return $_SESSION['temp_csrf_token'] ?? '';
}

/**
 * Verify CSRF token from request.
 *
 * @param string $tokenFromRequest CSRF token from request
 * @return bool Whether token is valid
 */
function validateCSRFToken(string $tokenFromRequest): bool {
    $session = validateActiveSession();
    if ($session) {
        // Timing-safe comparison
        return hash_equals($session['csrf_token'], $tokenFromRequest ?? '');
    }

    // Check temporary token
    if (isset($_SESSION['temp_csrf_token'])) {
        return hash_equals($_SESSION['temp_csrf_token'], $tokenFromRequest ?? '');
    }

    return false;
}
?>
