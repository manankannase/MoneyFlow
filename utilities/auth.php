<?php
/**
 * Authentication and Member Registration Module
 *
 * Handles member account creation, login verification, and credential management.
 *
 * Security Features:
 * - Passwords hashed using bcrypt with cost factor 12
 * - Timing-safe password verification prevents timing attacks
 * - Rate limiting on login attempts per IP address
 * - Generic error messages prevent username enumeration attacks
 * - No sensitive information leaked in error responses
 */

require_once __DIR__ . '/../settings/db_config.php';
require_once __DIR__ . '/validation.php';
require_once __DIR__ . '/session.php';

// Argon2id parameters for password hashing (PHP 8.x, libargon2 required).
// Argon2id is memory-hard, making GPU/ASIC cracking far more expensive than bcrypt.
// memory_cost: 64 MB, time_cost: 4 passes, threads: 2
define('PASSWORD_ALGO',    PASSWORD_ARGON2ID);
define('PASSWORD_OPTIONS', ['memory_cost' => 65536, 'time_cost' => 4, 'threads' => 2]);

// Rate limiting parameters
define('MAX_AUTH_ATTEMPTS', 5);            // per (IP + username) within the IP window
define('MAX_USERNAME_ATTEMPTS', 10);       // per username globally (catches IP rotation)
define('AUTH_IP_WINDOW', 7200);            // 2 hr cooldown per (IP + account)
define('AUTH_ACCOUNT_LOCKOUT_WINDOW', 21600); // 6 hr lockout per account after global threshold

/**
 * Register a new member account.
 *
 * @param string $accountId New member's username
 * @param string $emailAddr New member's email address
 * @param string $secretKey New member's password
 * @return array ['success' => bool, 'errorMsg' => string|null, 'memberId' => int|null]
 */
function createMemberAccount(string $accountId, string $emailAddr, string $secretKey): array {
    // Rate limit: max 5 successful registrations per IP per 24 hours.
    // Enforced here so no caller (script, alternate endpoint, etc.) can bypass it.
    $clientIp = retrieveClientIPAddress();
    $dbConn   = getPDOConnection();

    $regCountStmt = $dbConn->prepare(
        'SELECT COUNT(*) FROM registration_attempts
         WHERE ip_address = :ip
           AND created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)'
    );
    $regCountStmt->execute([':ip' => $clientIp]);
    if ((int) $regCountStmt->fetchColumn() >= 5) {
        return [
            'success'  => false,
            'errorMsg' => 'Account creation limit reached. A maximum of 5 accounts can be registered from your network per 24 hours. Please try again tomorrow.',
            'memberId' => null,
        ];
    }

    // Validate account identifier
    $accountIdValidation = validateAccountId($accountId);
    if (!$accountIdValidation['isValid']) {
        return [
            'success'   => false,
            'errorMsg'  => $accountIdValidation['errorMsg'],
            'memberId'  => null
        ];
    }

    // Validate email address
    $emailValidation = validateEmailAddress($emailAddr);
    if (!$emailValidation['isValid']) {
        return [
            'success'   => false,
            'errorMsg'  => $emailValidation['errorMsg'],
            'memberId'  => null
        ];
    }

    // Validate password strength
    $secretValidation = validateSecretKey($secretKey);
    if (!$secretValidation['isValid']) {
        return [
            'success'   => false,
            'errorMsg'  => $secretValidation['errorMsg'],
            'memberId'  => null
        ];
    }

    // Check if account ID or email already in use
    $checkQuery = $dbConn->prepare(
        'SELECT id FROM members WHERE account_name = :account_name OR email_address = :email_address LIMIT 1'
    );
    $checkQuery->execute([
        ':account_name'   => $accountId,
        ':email_address'  => $emailAddr
    ]);

    if ($checkQuery->fetch()) {
        // Generic message prevents user enumeration attacks
        return [
            'success'   => false,
            'errorMsg'  => 'Account name or email already registered.',
            'memberId'  => null
        ];
    }

    // Hash password using Argon2id
    $hashedSecret = password_hash($secretKey, PASSWORD_ALGO, PASSWORD_OPTIONS);

    if ($hashedSecret === false) {
        error_log('Password hashing failed during member registration');
        return [
            'success'   => false,
            'errorMsg'  => 'Registration failed. Please try again.',
            'memberId'  => null
        ];
    }

    // Create member with initial balance of 100 currency units
    $insertQuery = $dbConn->prepare(
        'INSERT INTO members (account_name, email_address, password_hash, account_balance) 
         VALUES (:account_name, :email_address, :password_hash, 100.00)'
    );

    try {
        $insertQuery->execute([
            ':account_name'   => $accountId,
            ':email_address'  => $emailAddr,
            ':password_hash'  => $hashedSecret,
        ]);

        $newMemberId = (int) $dbConn->lastInsertId();

        // Record this successful registration against the IP quota
        $dbConn->prepare(
            'INSERT INTO registration_attempts (ip_address) VALUES (:ip)'
        )->execute([':ip' => $clientIp]);

        return [
            'success'   => true,
            'errorMsg'  => null,
            'memberId'  => $newMemberId
        ];
    } catch (PDOException $e) {
        error_log('Member registration database error: ' . $e->getMessage());
        return [
            'success'   => false,
            'errorMsg'  => 'Registration failed. Please try again.',
            'memberId'  => null
        ];
    }
}

/**
 * Authenticate member with credentials.
 * Implements rate limiting to prevent brute force attacks.
 *
 * @param string $accountId Member's username
 * @param string $secretKey Member's password
 * @return array ['success' => bool, 'errorMsg' => string|null]
 */
function authenticateCredentials(string $accountId, string $secretKey): array {
    $clientIP = retrieveClientIPAddress();
    $dbConn = getPDOConnection();

    // Rate-limit by (ip_address + account_name) — 5 attempts per 15 min from same IP.
    // Short window keeps legitimate users from being locked out long if they mistype.
    $rateLimitQuery = $dbConn->prepare(
        'SELECT COUNT(*) as attempt_count FROM failed_auth_attempts
         WHERE ip_address = :ip_address
           AND account_name = :account_name
           AND created_at > DATE_SUB(NOW(), INTERVAL :window SECOND)'
    );
    $rateLimitQuery->bindValue(':ip_address',   $clientIP);
    $rateLimitQuery->bindValue(':account_name', $accountId);
    $rateLimitQuery->bindValue(':window', AUTH_IP_WINDOW, PDO::PARAM_INT);
    $rateLimitQuery->execute();
    $rateLimitResult = $rateLimitQuery->fetch();

    if ((int) $rateLimitResult['attempt_count'] >= MAX_AUTH_ATTEMPTS) {
        return [
            'success'   => false,
            'errorMsg'  => 'Too many login attempts. Please try again in 15 minutes.'
        ];
    }

    // Per-account global limit — catches attackers rotating IP addresses.
    // After 10 total failures against the same account from any IPs,
    // the account is locked for 24 hours regardless of which IP is used.
    $usernameRateQuery = $dbConn->prepare(
        'SELECT COUNT(*) as attempt_count FROM failed_auth_attempts
         WHERE account_name = :account_name
           AND created_at > DATE_SUB(NOW(), INTERVAL :window SECOND)'
    );
    $usernameRateQuery->bindValue(':account_name', $accountId);
    $usernameRateQuery->bindValue(':window', AUTH_ACCOUNT_LOCKOUT_WINDOW, PDO::PARAM_INT);
    $usernameRateQuery->execute();
    $usernameRateResult = $usernameRateQuery->fetch();

    if ((int) $usernameRateResult['attempt_count'] >= MAX_USERNAME_ATTEMPTS) {
        return [
            'success'   => false,
            'errorMsg'  => 'Account locked due to too many failed attempts. Please try again in 6 hours.'
        ];
    }

    // Fetch member by account ID
    $memberQuery = $dbConn->prepare(
        'SELECT id, password_hash FROM members WHERE account_name = :account_name LIMIT 1'
    );
    $memberQuery->execute([':account_name' => $accountId]);
    $memberRecord = $memberQuery->fetch();

    // Generic message for failed login (prevents account enumeration)
    if (!$memberRecord || !password_verify($secretKey, $memberRecord['password_hash'])) {
        // FIX V7: Log failed attempt keyed by (ip_address, account_name)
        $logFailQuery = $dbConn->prepare(
            'INSERT INTO failed_auth_attempts (ip_address, account_name) VALUES (:ip_address, :account_name)'
        );
        $logFailQuery->execute([':ip_address' => $clientIP, ':account_name' => $accountId]);

        return [
            'success'   => false,
            'errorMsg'  => 'Invalid credentials.'
        ];
    }

    // FIX V7: Do NOT clear failed_auth_attempts on success.
    // Clearing on success was the bypass: attacker tried 4 times vs victim,
    // then logged into their own account, which reset the whole IP counter.
    // Now the windows expire naturally (AUTH_IP_WINDOW / AUTH_ACCOUNT_LOCKOUT_WINDOW).

    // Auto-upgrade legacy bcrypt hashes to Argon2id on successful login.
    // password_needs_rehash() returns true when the stored hash uses a different
    // algorithm or weaker parameters than the current PASSWORD_ALGO/OPTIONS.
    if (password_needs_rehash($memberRecord['password_hash'], PASSWORD_ALGO, PASSWORD_OPTIONS)) {
        $newHash = password_hash($secretKey, PASSWORD_ALGO, PASSWORD_OPTIONS);
        if ($newHash !== false) {
            $rehashQuery = $dbConn->prepare(
                'UPDATE members SET password_hash = :hash WHERE id = :id'
            );
            $rehashQuery->execute([':hash' => $newHash, ':id' => $memberRecord['id']]);
        }
    }

    // Initialize new session
    initializeNewSession((int) $memberRecord['id']);

    return [
        'success'   => true,
        'errorMsg'  => null
    ];
}


/**
 * Admin bulk-seeding account creator — CLI only.
 *
 * Bypasses the per-IP registration rate limit and password-strength validation
 * so that the deployment seed script (create_accounts.php) can insert all
 * course accounts in one run.
 *
 * SECURITY: This function hard-aborts if called outside CLI context so it
 * cannot be reached via any HTTP request, regardless of how it is invoked.
 *
 * @param string $accountId Username
 * @param string $emailAddr Email address
 * @param string $secretKey Plain-text password (will be Argon2id-hashed)
 * @return array ['success' => bool, 'errorMsg' => string|null, 'memberId' => int|null]
 */
function createMemberAccountAdmin(string $accountId, string $emailAddr, string $secretKey): array {
    // Hard gate — this function must never be reachable over HTTP.
    if (php_sapi_name() !== 'cli') {
        http_response_code(403);
        exit('Forbidden');
    }

    $dbConn = getPDOConnection();

    // Validate account identifier format only (no rate-limit, no password-strength check)
    $accountIdValidation = validateAccountId($accountId);
    if (!$accountIdValidation['isValid']) {
        return ['success' => false, 'errorMsg' => $accountIdValidation['errorMsg'], 'memberId' => null];
    }

    $emailValidation = validateEmailAddress($emailAddr);
    if (!$emailValidation['isValid']) {
        return ['success' => false, 'errorMsg' => $emailValidation['errorMsg'], 'memberId' => null];
    }

    if (empty($secretKey)) {
        return ['success' => false, 'errorMsg' => 'Password is required.', 'memberId' => null];
    }

    // Check for duplicates
    $checkQuery = $dbConn->prepare(
        'SELECT id FROM members WHERE account_name = :account_name OR email_address = :email_address LIMIT 1'
    );
    $checkQuery->execute([':account_name' => $accountId, ':email_address' => $emailAddr]);
    if ($checkQuery->fetch()) {
        return ['success' => false, 'errorMsg' => 'Account name or email already registered.', 'memberId' => null];
    }

    $hashedSecret = password_hash($secretKey, PASSWORD_ALGO, PASSWORD_OPTIONS);
    if ($hashedSecret === false) {
        error_log('Password hashing failed during admin bulk registration');
        return ['success' => false, 'errorMsg' => 'Registration failed.', 'memberId' => null];
    }

    $insertQuery = $dbConn->prepare(
        'INSERT INTO members (account_name, email_address, password_hash, account_balance)
         VALUES (:account_name, :email_address, :password_hash, 100.00)'
    );

    try {
        $insertQuery->execute([
            ':account_name'  => $accountId,
            ':email_address' => $emailAddr,
            ':password_hash' => $hashedSecret,
        ]);
        return ['success' => true, 'errorMsg' => null, 'memberId' => (int) $dbConn->lastInsertId()];
    } catch (PDOException $e) {
        error_log('Admin bulk registration DB error: ' . $e->getMessage());
        return ['success' => false, 'errorMsg' => 'Registration failed.', 'memberId' => null];
    }
}

?>
