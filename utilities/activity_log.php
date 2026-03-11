<?php
/**
 * Activity Logging (Audit Trail)
 *
 * Logs page accesses and authentication events.
 * Does NOT log sensitive data (passwords, tokens, hashes).
 */

require_once __DIR__ . '/../settings/db_config.php';

/**
 * Log a page access event.
 *
 * @param int|null $memberId     Authenticated member ID, or null if guest.
 * @param string|null $accountName Account name for the log entry.
 */
function logPageAccess(?int $memberId, ?string $accountName): void {
    $pagePath  = substr($_SERVER['REQUEST_URI'] ?? '', 0, 255);
    $ipAddress = getClientIpForLog();
    $userAgent = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 512);

    try {
        $pdo  = getDbConnection();
        $stmt = $pdo->prepare(
            'INSERT INTO event_chronicle
                 (member_id, account_name, page_path, ip_address, user_agent)
             VALUES (:member_id, :account_name, :page_path, :ip_address, :user_agent)'
        );
        $stmt->execute([
            ':member_id'    => $memberId,
            ':account_name' => $accountName,
            ':page_path'    => $pagePath,
            ':ip_address'   => $ipAddress,
            ':user_agent'   => $userAgent,
        ]);
    } catch (PDOException $e) {
        error_log('MoneyFlow logPageAccess error: ' . $e->getMessage());
    }
}

/**
 * Record a failed authentication attempt for rate-limiting.
 *
 * @param string $accountName The account name attempted (may be invalid).
 */
function recordFailedAuth(string $accountName): void {
    $ipAddress = getClientIpForLog();

    try {
        $pdo  = getDbConnection();
        $stmt = $pdo->prepare(
            'INSERT INTO failed_auth_attempts (ip_address, account_name)
             VALUES (:ip_address, :account_name)'
        );
        $stmt->execute([
            ':ip_address'   => $ipAddress,
            ':account_name' => substr($accountName, 0, 50),
        ]);
    } catch (PDOException $e) {
        error_log('MoneyFlow recordFailedAuth error: ' . $e->getMessage());
    }
}

/**
 * Check if an IP address is rate-limited (too many recent failures).
 *
 * @param int $maxAttempts Maximum failures allowed within the window.
 * @param int $windowSeconds Time window in seconds.
 */
function isRateLimited(int $maxAttempts = 10, int $windowSeconds = 900): bool {
    $ipAddress = getClientIpForLog();

    try {
        $pdo  = getDbConnection();
        $stmt = $pdo->prepare(
            'SELECT COUNT(*) FROM failed_auth_attempts
             WHERE ip_address = :ip_address
               AND created_at > DATE_SUB(NOW(), INTERVAL :window SECOND)'
        );
        $stmt->execute([
            ':ip_address' => $ipAddress,
            ':window'     => $windowSeconds,
        ]);
        $count = (int) $stmt->fetchColumn();
        return $count >= $maxAttempts;
    } catch (PDOException $e) {
        error_log('MoneyFlow isRateLimited error: ' . $e->getMessage());
        return false;
    }
}

/**
 * Get client IP (shared helper for logging — same logic as session.php).
 */
function getClientIpForLog(): string {
    foreach (['HTTP_X_FORWARDED_FOR', 'HTTP_CLIENT_IP', 'REMOTE_ADDR'] as $key) {
        if (!empty($_SERVER[$key])) {
            $ip = trim(explode(',', $_SERVER[$key])[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }
    }
    return '0.0.0.0';
}
