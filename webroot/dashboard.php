<?php
/**
 * Member Dashboard
 * Main page for authenticated members showing balance and quick actions
 */

define('APP_BASE', dirname(__DIR__));

require_once APP_BASE . '/utilities/security.php';
require_once APP_BASE . '/utilities/session.php';
require_once APP_BASE . '/utilities/operations.php';
require_once APP_BASE . '/utilities/validation.php';
require_once APP_BASE . '/utilities/activity_log.php';

applySecurityHeaders();

$session = validateActiveSession();
if (!$session) {
    header('Location: /signin.php');
    exit;
}

chroniclePageAccess('dashboard.php', $session);

// Fetch member profile
$memberProfile = fetchMemberProfile($session['member_id']);
if (!$memberProfile) {
    destroyActiveSession();
    header('Location: /signin.php');
    exit;
}

// Get recent transfers
$recentTransfers = retrieveMemberTransferHistory($session['member_id'], 1, 5);

$pageTitle = 'Dashboard';
require_once APP_BASE . '/layouts/header.php';
?>

<div class="dashboard-container">
    <div class="dashboard-grid">
        <section class="balance-section">
            <h2 class="section-title">Account Overview</h2>
            <div class="balance-card">
                <p class="balance-label">Current Balance</p>
                <p class="balance-amount">₹<?php echo number_format((float)$memberProfile['account_balance'], 2); ?></p>
                <p class="balance-info">Account ID: <?php echo escapeForHTML($memberProfile['id']); ?> | Name: <?php echo escapeForHTML($memberProfile['account_name']); ?></p>
            </div>
        </section>

        <section class="quick-actions">
            <h2 class="section-title">Quick Actions</h2>
            <div class="action-buttons">
                <a href="/transfer.php" class="btn btn-primary">Send Money</a>
                <a href="/search.php" class="btn btn-outline">Find Member</a>
                <a href="/transaction_history.php" class="btn btn-outline">View History</a>
                <a href="/account_settings.php" class="btn btn-outline">Settings</a>
            </div>
        </section>

        <section class="recent-activity">
            <h2 class="section-title">Recent Transfers</h2>
            <?php if (!empty($recentTransfers)): ?>
                <table class="activity-table">
                    <thead>
                        <tr>
                            <th>Type</th>
                            <th>Person</th>
                            <th>Amount</th>
                            <th>Date</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($recentTransfers as $transfer): ?>
                            <tr>
                                <td>
                                    <?php if ((int)$transfer['sender_id'] === $session['member_id']): ?>
                                        <span class="tag tag-sent">Sent</span>
                                    <?php else: ?>
                                        <span class="tag tag-received">Received</span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <?php if ((int)$transfer['sender_id'] === $session['member_id']): ?>
                                        → <?php echo escapeForHTML($transfer['recipient_name']); ?>
                                    <?php else: ?>
                                        ← <?php echo escapeForHTML($transfer['sender_name']); ?>
                                    <?php endif; ?>
                                </td>
                                <td>₹<?php echo number_format((float)$transfer['transfer_amount'], 2); ?></td>
                                <td><?php echo escapeForHTML(date('M d, Y', strtotime($transfer['created_at']))); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php else: ?>
                <p class="text-muted">No transfer activity yet.</p>
            <?php endif; ?>
        </section>
    </div>
</div>

<?php require_once APP_BASE . '/layouts/footer.php'; ?>
