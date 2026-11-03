<?php
/**
 * Transaction History / Transfer Log
 * Shows all transfers for the authenticated member
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

chroniclePageAccess('transaction_history.php', $session);

$pageNum = is_string($_GET['page'] ?? null) ? intval($_GET['page']) : 1;
if ($pageNum < 1) $pageNum = 1;
// FIX #23: Cap page number to prevent huge OFFSET scans on large tables.
// ?page=999999999 → MySQL scans ~20 billion index rows. 10,000 pages × 20 = 200,000 rows max.
if ($pageNum > 10000) $pageNum = 10000;

// Fetch transfers and total count
$transfers = retrieveMemberTransferHistory($session['member_id'], $pageNum, 20);
$totalTransfers = countMemberTransfers($session['member_id']);
$totalPages = ceil($totalTransfers / 20);

$pageTitle = 'Transfer History';
require_once APP_BASE . '/layouts/header.php';
?>

<div class="history-container">
    <div class="history-card">
        <h2 class="card-title">Transfer History</h2>

        <?php if (!empty($transfers)): ?>
            <div class="transaction-header">
                <div class="header-row">
                    <div class="header-col">Txn. ID</div>
                    <div class="header-col">DATE</div>
                    <div class="header-col">TYPE</div>
                    <div class="header-col">USER</div>
                    <div class="header-col">AMOUNT</div>
                    <div class="header-col">COMMENT</div>
                </div>
            </div>

            <table class="history-table">
                <thead>
                    <tr>
                        <th>Txn. ID</th>
                        <th>Date</th>
                        <th>Type</th>
                        <th>User</th>
                        <th>Amount</th>
                        <th>Comment</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($transfers as $txn): ?>
                        <tr>
                            <td><?php echo escapeForHTML($txn['id']); ?></td>
                            <td><?php echo escapeForHTML(date('M d, Y H:i', strtotime($txn['created_at']))); ?></td>
                            <td>
                                <?php if ((int)$txn['sender_id'] === $session['member_id']): ?>
                                    <span class="badge badge-sent">Sent</span>
                                <?php else: ?>
                                    <span class="badge badge-received">Received</span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <?php if ((int)$txn['sender_id'] === $session['member_id']): ?>
                                    → <?php echo escapeForHTML($txn['recipient_name']); ?>
                                <?php else: ?>
                                    ← <?php echo escapeForHTML($txn['sender_name']); ?>
                                <?php endif; ?>
                            </td>
                            <td>₹<?php echo number_format((float)$txn['transfer_amount'], 2); ?></td>
                            <td title="<?php echo escapeForHTML($txn['memo_text'] ?? ''); ?>"><?php echo escapeForHTML($txn['memo_text'] ?? '-'); ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>

            <!-- Pagination -->
            <?php if ($totalPages > 1): ?>
                <div class="pagination">
                    <?php if ($pageNum > 1): ?>
                        <a href="/transaction_history.php?page=1" class="paginate-link">First</a>
                        <a href="/transaction_history.php?page=<?php echo $pageNum - 1; ?>" class="paginate-link">Previous</a>
                    <?php endif; ?>

                    <span class="paginate-info">Page <?php echo $pageNum; ?> of <?php echo $totalPages; ?></span>

                    <?php if ($pageNum < $totalPages): ?>
                        <a href="/transaction_history.php?page=<?php echo $pageNum + 1; ?>" class="paginate-link">Next</a>
                        <a href="/transaction_history.php?page=<?php echo $totalPages; ?>" class="paginate-link">Last</a>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
        <?php else: ?>
            <p class="text-muted">No transfer history available.</p>
        <?php endif; ?>
    </div>
</div>

<?php require_once APP_BASE . '/layouts/footer.php'; ?>
