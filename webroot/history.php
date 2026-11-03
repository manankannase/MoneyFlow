<?php
/**
 * Transfer History Page
 */
require_once __DIR__ . '/../utilities/security.php';
require_once __DIR__ . '/../utilities/session.php';
require_once __DIR__ . '/../utilities/operations.php';
require_once __DIR__ . '/../utilities/activity_log.php';
require_once __DIR__ . '/../utilities/validation.php';

sendSecurityHeaders();

$session = validateSession();
if (!$session) {
    header('Location: /login.php');
    exit;
}

logPageAccess((int) $session['member_id'], $session['account_name']);

$page      = max(1, (int) ($_GET['page'] ?? 1));
$transfers = getTransferHistory((int) $session['member_id'], $page, 20);
$pageTitle = 'Transfer History';

require_once __DIR__ . '/../layouts/header.php';
?>
<div class="history-container">
    <h1>Transfer History</h1>
    <?php if (empty($transfers)): ?>
        <p class="empty-state">No transfers found.</p>
    <?php else: ?>
        <table class="transfers-table">
            <thead>
                <tr>
                    <th>Date</th>
                    <th>From</th>
                    <th>To</th>
                    <th>Amount</th>
                    <th>Memo</th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($transfers as $tx): ?>
                <tr class="<?= $tx['sender_name'] === $session['account_name'] ? 'outgoing' : 'incoming' ?>">
                    <td><?= h(date('d M Y, H:i', strtotime($tx['created_at']))) ?></td>
                    <td><?= h($tx['sender_name']) ?></td>
                    <td><?= h($tx['recipient_name']) ?></td>
                    <td class="amount <?= $tx['sender_name'] === $session['account_name'] ? 'debit' : 'credit' ?>">
                        <?= $tx['sender_name'] === $session['account_name'] ? '−' : '+' ?>₹<?= h(number_format((float)$tx['transfer_amount'], 2)) ?>
                    </td>
                    <td><?= h($tx['memo_text']) ?></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        <div class="pagination">
            <?php if ($page > 1): ?>
                <a href="?page=<?= $page - 1 ?>" class="btn btn-secondary">← Previous</a>
            <?php endif; ?>
            <?php if (count($transfers) === 20): ?>
                <a href="?page=<?= $page + 1 ?>" class="btn btn-secondary">Next →</a>
            <?php endif; ?>
        </div>
    <?php endif; ?>
</div>
<?php require_once __DIR__ . '/../layouts/footer.php'; ?>
