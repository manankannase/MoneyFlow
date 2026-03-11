<?php
/**
 * Dashboard Page
 */
require_once __DIR__ . '/../utilities/security.php';
require_once __DIR__ . '/../utilities/session.php';
require_once __DIR__ . '/../utilities/activity_log.php';
require_once __DIR__ . '/../utilities/validation.php';

sendSecurityHeaders();

$session = validateSession();
if (!$session) {
    header('Location: /login.php');
    exit;
}

logPageAccess((int) $session['member_id'], $session['account_name']);

$pageTitle = 'Dashboard';

require_once __DIR__ . '/../layouts/header.php';
?>
<div class="dashboard">
    <h1>Welcome, <?= h($session['account_name']) ?>!</h1>
    <div class="balance-card">
        <span class="balance-label">Current Balance</span>
        <span class="balance-amount">₹<?= h(number_format((float)$session['account_balance'], 2)) ?></span>
    </div>
    <div class="quick-actions">
        <a href="/transfer.php" class="action-card">
            <span class="icon">💸</span>
            <span>Send Money</span>
        </a>
        <a href="/history.php" class="action-card">
            <span class="icon">📋</span>
            <span>Transfer History</span>
        </a>
        <a href="/search.php" class="action-card">
            <span class="icon">🔍</span>
            <span>Find Members</span>
        </a>
        <a href="/profile.php" class="action-card">
            <span class="icon">👤</span>
            <span>My Profile</span>
        </a>
    </div>
</div>
<?php require_once __DIR__ . '/../layouts/footer.php'; ?>
