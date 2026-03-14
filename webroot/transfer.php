<?php


define('APP_BASE', dirname(__DIR__));

require_once APP_BASE . '/utilities/security.php';
require_once APP_BASE . '/utilities/session.php';
require_once APP_BASE . '/utilities/operations.php';
require_once APP_BASE . '/utilities/validation.php';
require_once APP_BASE . '/utilities/activity_log.php';
require_once APP_BASE . '/settings/db_config.php';

applySecurityHeaders();

$session = validateActiveSession();
if (!$session) {
    header('Location: /signin.php');
    exit;
}

chroniclePageAccess('transfer.php', $session);

$errorMsg   = '';
$successMsg = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $errorMsg = 'Security validation failed.';
    } else {
        $transferToken = trim($_POST['transfer_token'] ?? '');
        $memoText      = trim($_POST['memo_text'] ?? '');

        if (empty($transferToken)) {
            $errorMsg = 'Transfer token missing. Please ensure JavaScript is enabled.';
        } else {
            $payload = decryptTransferToken($transferToken);

            if ($payload === null) {
                error_log("TAMPERING ATTEMPT: AES-GCM decryption failed.");
                $errorMsg = 'Transfer token is invalid or has been tampered with.';
            } elseif (intval($payload['sender_id']) !== $session['member_id']) {
                error_log("TAMPERING ATTEMPT: token sender_id mismatch.");
                $errorMsg = 'Transfer token mismatch. Please try again.';
            } elseif (!isset($_SESSION['transfer_nonce']) || !hash_equals($_SESSION['transfer_nonce'], $payload['nonce'])) {
                error_log("REPLAY ATTEMPT: Nonce mismatch.");
                $errorMsg = 'Transfer token has already been used or is invalid.';
            } else {
                // Consume session nonce — one-time use
                unset($_SESSION['transfer_nonce']);

                $transactionId = $payload['nonce']; // contains the 64-char transaction_id
                $dbConn        = getPDOConnection();
                $clientIp      = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

                $fetchStmt = $dbConn->prepare(
                    'SELECT sender_id, recipient_id, amount, expires_at, used
                     FROM pending_transfers
                     WHERE transaction_id = :txn_id
                     LIMIT 1'
                );
                $fetchStmt->execute([':txn_id' => $transactionId]);
                $pendingTxn = $fetchStmt->fetch();

                if (!$pendingTxn) {
                    error_log("INVALID TXN: transaction_id not found | ip={$clientIp}");
                    $errorMsg = 'Transfer record not found. Please try again.';
                } elseif ($pendingTxn['used']) {
                    error_log("REPLAY ATTEMPT: transaction_id already used | ip={$clientIp}");
                    $errorMsg = 'This transfer has already been executed.';
                } elseif (strtotime($pendingTxn['expires_at']) < time()) {
                    $errorMsg = 'Transfer has expired. Please initiate a new transfer.';
                } elseif (intval($pendingTxn['sender_id']) !== $session['member_id']) {
                    // Transaction belongs to a different user — cross-account swap attempt
                    error_log("TAMPERING DETECTED: DB sender_id mismatch | ip={$clientIp}");
                    $errorMsg = 'Transfer authorization mismatch.';
                } else {
                    // Mark as used atomically before executing — prevents double-spend
                    $markUsed = $dbConn->prepare(
                        'UPDATE pending_transfers SET used = 1
                         WHERE transaction_id = :txn_id AND used = 0'
                    );
                    $markUsed->execute([':txn_id' => $transactionId]);

                    if ($markUsed->rowCount() === 0) {
                        // Another request consumed it first (race condition protection)
                        $errorMsg = 'This transfer has already been executed.';
                    } else {
                        // Validate memo (only user-supplied field)
                        $memoValidation = validateTransferMemo($memoText);
                        if (!$memoValidation['isValid']) {
                            $errorMsg = $memoValidation['errorMsg'];
                        } else {
                            // Execute using EXCLUSIVELY DB-stored values
                            $transferResult = executeMoneyTransfer(
                                intval($pendingTxn['sender_id']),
                                intval($pendingTxn['recipient_id']),
                                round(floatval($pendingTxn['amount']), 2),
                                $memoText
                            );

                            if ($transferResult['success']) {
                                $successMsg = 'Transfer completed successfully!';
                                chroniclePageAccess('transfer.php (success)', $session);
                            } else {
                                $errorMsg = $transferResult['errorMsg'];
                            }
                        }
                    }
                }
            }
        }
    }
}

$pageTitle = 'Send Money';
$csrfToken = produceCSRFToken();

require_once APP_BASE . '/layouts/header.php';
?>

<div class="transfer-container">
    <div class="transfer-card">
        <h2 class="card-title">Send Money</h2>

        <?php if ($errorMsg): ?>
            <div class="alert alert-error"><?php echo escapeForHTML($errorMsg); ?></div>
        <?php endif; ?>

        <?php if ($successMsg): ?>
            <div class="alert alert-success"><?php echo escapeForHTML($successMsg); ?></div>
        <?php endif; ?>

        <form method="POST" action="/transfer.php" id="transferForm">
            <input type="hidden" name="csrf_token" value="<?php echo escapeForHTML($csrfToken); ?>">
            <input type="hidden" name="transfer_token" id="transfer_token" value="">

            <div class="form-group">
                <label for="recipient_id" class="form-label">Recipient Account ID</label>
                <input type="number" id="recipient_id" name="recipient_id" class="form-input"
                       required placeholder="Enter recipient's account ID" min="1"
                       value="<?php echo isset($_GET['to']) ? escapeForHTML($_GET['to']) : ''; ?>">
            </div>

            <div class="form-group">
                <label for="transfer_amount" class="form-label">Amount (₹)</label>
                <input type="number" id="transfer_amount" name="transfer_amount"
                       class="form-input" required step="0.01" min="0.01"
                       placeholder="0.00">
            </div>

            
            <div id="transferErrorPanel" style="display:none;" class="alert alert-error"></div>

           
            <div id="confirmPanel" style="display:none;" class="alert alert-success">
                Sending <strong id="confirmAmount"></strong> to
                <strong id="confirmRecipient"></strong>. Click Send Money to confirm.
            </div>

            <div class="form-group">
                <label for="memo_text" class="form-label">Memo (Optional)</label>
                <textarea id="memo_text" name="memo_text" class="form-textarea"
                          maxlength="500" rows="3"
                          placeholder="Add a note for this transfer..."></textarea>
                <small class="form-hint">500 characters max</small>
            </div>

            <button type="submit" class="btn btn-primary btn-full">Send Money</button>
        </form>

        <div class="form-footer">
            <a href="/search.php" class="link">Can't find the recipient?</a>
        </div>
    </div>
</div>

<?php require_once APP_BASE . '/layouts/footer.php'; ?>
