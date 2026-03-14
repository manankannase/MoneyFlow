<?php
/**
 * Home / Welcome Page
 * Displays welcome screen to guests, redirects authenticated members to dashboard
 */

define('APP_BASE', dirname(__DIR__));

require_once APP_BASE . '/utilities/security.php';
require_once APP_BASE . '/utilities/session.php';
require_once APP_BASE . '/utilities/validation.php';
require_once APP_BASE . '/utilities/activity_log.php';

applySecurityHeaders();

$session = validateActiveSession();

// Log page access
chroniclePageAccess('home.php', $session);

if ($session) {
    header('Location: /dashboard.php');
    exit;
}

$pageTitle = 'Welcome';
require_once APP_BASE . '/layouts/header.php';
?>

<div class="welcome-container">
    <div class="welcome-card">
        <div class="welcome-header">
            <h1 class="welcome-title">MoneyFlow</h1>
            <p class="welcome-subtitle">Secure Financial Transfers Made Simple</p>
        </div>

        <p class="welcome-description">
            MoneyFlow is a cutting-edge secure platform for swift and safe money transfers. 
            Join our community of secure financial transactions.
        </p>

        <div class="button-group">
            <a href="/signin.php" class="btn btn-primary">Sign In</a>
            <a href="/signup.php" class="btn btn-secondary">Create Account</a>
        </div>
    </div>
</div>

<?php require_once APP_BASE . '/layouts/footer.php'; ?>
