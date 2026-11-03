<?php
/**
 * Logout / Sign Out
 * Destroys session and logs out member
 *
 * SECURITY FIX: Requires POST with CSRF token to prevent forced-logout attacks.
 * GET requests redirect to dashboard without destroying the session.
 */

define('APP_BASE', dirname(__DIR__));

require_once APP_BASE . '/utilities/security.php';
require_once APP_BASE . '/utilities/session.php';
require_once APP_BASE . '/utilities/activity_log.php';

applySecurityHeaders();

$session = validateActiveSession();

// SECURITY FIX: Only accept POST requests with valid CSRF token
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    // GET request — do NOT destroy session (prevents img-tag forced logout)
    header('Location: /dashboard.php');
    exit;
}

// Validate CSRF token
$csrfToken = $_POST['csrf_token'] ?? '';
if (!$session || !validateCSRFToken($csrfToken)) {
    header('Location: /dashboard.php');
    exit;
}

chroniclePageAccess('logout.php', $session);

// Destroy the PHP native session as well
if (session_status() === PHP_SESSION_ACTIVE) {
    session_destroy();
}

// Destroy custom session
destroyActiveSession();

// Redirect to home
header('Location: /index.php');
exit;
?>
