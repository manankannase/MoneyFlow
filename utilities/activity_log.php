<?php
/**
 * Event Chronicle and Activity Logging System
 *
 * Maintains comprehensive audit logs for all user activities.
 * Captures: Page accessed, Member account, Timestamp, Client IP address, User-Agent
 * 
 * Purpose: Security auditing and compliance with regulations.
 */

require_once __DIR__ . '/../settings/db_config.php';
require_once __DIR__ . '/session.php';

/**
 * Record user activity in event chronicle.
 *
 * @param string     $pageUri Page path being accessed
 * @param array|null $sessionData Session array (null for unauthenticated access)
 */
function chroniclePageAccess(string $pageUri, ?array $sessionData = null): void {
    try {
        $dbConn = getPDOConnection();

        $memberId   = $sessionData['member_id'] ?? null;
        $accountId  = $sessionData['account_name'] ?? null;
        $clientIP   = retrieveClientIPAddress();
        $userAgent  = $_SERVER['HTTP_USER_AGENT'] ?? 'unidentified_agent';
        // Sanitize to prevent stored XSS if logs are ever displayed in an admin panel
        $userAgent  = htmlspecialchars($userAgent, ENT_QUOTES | ENT_HTML5, 'UTF-8'); 

        // Prevent overly long user-agent strings
        if (mb_strlen($userAgent, 'UTF-8') > 500) {
            $userAgent = mb_substr($userAgent, 0, 500, 'UTF-8');
        }

        $logQuery = $dbConn->prepare(
            'INSERT INTO event_chronicle (member_id, account_name, page_path, ip_address, user_agent)
             VALUES (:member_id, :account_name, :page_path, :ip_address, :user_agent)'
        );

        $logQuery->execute([
            ':member_id'    => $memberId,
            ':account_name' => $accountId,
            ':page_path'    => $pageUri,
            ':ip_address'   => $clientIP,
            ':user_agent'   => $userAgent,
        ]);
    } catch (PDOException $e) {
        // IMPORTANT: Logging failures should not disrupt application
        error_log('Event chronicle insertion failed: ' . $e->getMessage());
    }
}


?>
