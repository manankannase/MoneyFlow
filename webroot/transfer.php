<?php
/**
 * Transfer / Send Money Page
 *
 * DB Intent Binding Flow (industry-standard defense against proxy tampering):
 *
 *  1. User fills recipient_id + amount and clicks Submit.
 *  2. JS POSTs to api_transfer_signature.php with CSRF + recipient + amount.
 *  3. Server validates, writes a pending_transfers DB row with those values,
 *     and returns an AES-256-GCM token containing only the opaque transaction_id.
 *  4. JS places the token in a hidden field and submits the form.
 *  5. This page decrypts the token → gets transaction_id → looks up the DB row
 *     → executes using ONLY the DB-stored recipient and amount.
 *
 * Why this defeats Burp Suite interception of the token-issuance request:
 *   Even if Burp changes recipient/amount in step 2, the attacker is changing
 *   what gets written into the DB row — but they can only do this for their OWN
 *   authenticated session. The sender_id in the DB row and the token are both
 *   bound to the session. An attacker cannot issue a pending transfer for another
 *   user's account; they can only redirect their own money.
 *
 *   For a genuine attack on a victim's account, the attacker would need to also
 *   control the victim's authenticated session — at which point the session
 *   security (not the transfer flow) is the correct layer to harden.
 */

define('APP_BASE', dirname(__DIR__));

require_once APP_BASE . '/utilities/security.php';
require_once APP_BASE . '/utilities/session.php';
require_once APP_BASE . '/utilities/operations.php';
require_once APP_BASE . '/utilities/validation.php';
require_once APP_BASE . '/utilities/activity_log.php';
// db_config.php is pulled in transitively via session.php → db_config.php,
// so getPDOConnection() is available without an extra require here.

applySecurityHeaders();

$session = validateActiveSession();
if (!$session) {
    header('Location: /signin.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    chroniclePageAccess('transfer.php', $session);
}

// FIX #3: Step-up re-authentication for financial operations.
// OWASP ASVS V2.2.1 / PCI DSS 8.4: high-value actions require recent password
// confirmation even when the session is valid. A session cookie found on a
// shared machine or via XSS must NOT be sufficient to drain the account.
//
// Step-up is valid for 15 minutes. After that, password must be re-entered.
define('STEPUP_WINDOW', 900); // 15 minutes

$stepupError    = '';
$stepupVerified = isset($_SESSION['stepup_verified_at'])
    && (time() - (int) $_SESSION['stepup_verified_at']) < STEPUP_WINDOW;

// Handle step-up form POST
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['stepup_submit'])) {
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $stepupError = 'Security validation failed.';
    } else {
        $dbConn        = getPDOConnection();
        $clientIP      = retrieveClientIPAddress();
        $stepupRateKey = 'stepup:' . $session['member_id'];

        // Rate limit step-up: max 5 wrong attempts per IP per 15 minutes.
        // Uses the same failed_auth_attempts table as login to avoid schema changes.
        $stepupRateQuery = $dbConn->prepare(
            'SELECT COUNT(*) as attempt_count FROM failed_auth_attempts
             WHERE ip_address  = :ip
               AND account_name = :key
               AND created_at  > DATE_SUB(NOW(), INTERVAL 900 SECOND)'
        );
        $stepupRateQuery->bindValue(':ip',  $clientIP);
        $stepupRateQuery->bindValue(':key', $stepupRateKey);
        $stepupRateQuery->execute();

        if ((int) $stepupRateQuery->fetch()['attempt_count'] >= 5) {
            $stepupError = 'Too many incorrect attempts. Please wait 15 minutes before trying again.';
        } else {
            $stepupPassword = $_POST['stepup_password'] ?? '';
            $hashQuery = $dbConn->prepare(
                'SELECT password_hash FROM members WHERE id = :id LIMIT 1'
            );
            $hashQuery->execute([':id' => $session['member_id']]);
            $memberRecord = $hashQuery->fetch();

            if ($memberRecord && password_verify($stepupPassword, $memberRecord['password_hash'])) {
                $_SESSION['stepup_verified_at'] = time();
                $stepupVerified = true;
                // Redirect to GET so refreshing does not re-submit the password form
                header('Location: /transfer.php' . (isset($_GET['to']) && is_string($_GET['to']) ? '?to=' . (int)$_GET['to'] : ''));
                exit;
            } else {
                // Record failed step-up attempt for rate limiting
                $dbConn->prepare(
                    'INSERT INTO failed_auth_attempts (ip_address, account_name) VALUES (:ip, :key)'
                )->execute([':ip' => $clientIP, ':key' => $stepupRateKey]);
                $stepupError = 'Incorrect password. Please try again.';
            }
        }
    }
}

// If step-up not verified, show the password confirmation form and stop here
if (!$stepupVerified) {
    $csrfToken = produceCSRFToken();
    $pageTitle  = 'Confirm Identity';
    require_once APP_BASE . '/layouts/header.php';
    ?>
    <div class="transfer-container">
        <div class="transfer-card">
            <h2 class="card-title">Confirm Your Identity</h2>
            <p class="text-muted" style="margin-bottom:1rem;">
                For your security, please re-enter your password before sending money.
                This confirmation is valid for 15 minutes.
            </p>

            <?php if ($stepupError): ?>
                <div class="alert alert-error"><?php echo escapeForHTML($stepupError); ?></div>
            <?php endif; ?>

            <form method="POST" action="/transfer.php<?php echo (isset($_GET['to']) && is_string($_GET['to'])) ? '?to=' . (int)$_GET['to'] : ''; ?>">
                <input type="hidden" name="csrf_token" value="<?php echo escapeForHTML($csrfToken); ?>">
                <input type="hidden" name="stepup_submit" value="1">

                <div class="form-group">
                    <label for="stepup_password" class="form-label">Password</label>
                    <div class="password-container">
                        <input type="password" id="stepup_password" name="stepup_password"
                               class="form-input" required maxlength="72" autofocus
                               placeholder="Enter your current password">
                        <button type="button" class="password-toggle">Show</button>
                    </div>
                </div>

                <button type="submit" class="btn btn-primary btn-full">Confirm &amp; Continue</button>
            </form>

            <div class="form-footer">
                <a href="/dashboard.php" class="link">Cancel — go to Dashboard</a>
            </div>
        </div>
    </div>
    <?php
    require_once APP_BASE . '/layouts/footer.php';
    exit;
}

$errorMsg   = '';
$successMsg = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $errorMsg = 'Security validation failed.';
    } else {
        $transferToken = is_string($_POST['transfer_token'] ?? null) ? trim($_POST['transfer_token']) : '';
        $memoText      = is_string($_POST['memo_text'] ?? null) ? trim($_POST['memo_text']) : '';

        if (empty($transferToken)) {
            $errorMsg = 'Transfer token missing. Please ensure JavaScript is enabled.';
        } else {
            // Step 1: Decrypt AES-256-GCM token — tampered blob returns null immediately
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

                // Step 2: Look up the pending transfer in the database.
                // The transaction_id is inside the encrypted token (field 'nonce' repurposed
                // as the opaque DB key). ALL transfer values come from the DB row —
                // never from the client's POST body.
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
                       value="<?php echo (isset($_GET['to']) && is_string($_GET['to'])) ? escapeForHTML($_GET['to']) : ''; ?>">
            </div>

            <div class="form-group">
                <label for="transfer_amount" class="form-label">Amount (₹)</label>
                <input type="number" id="transfer_amount" name="transfer_amount"
                       class="form-input" required step="0.01" min="0.01"
                       placeholder="0.00">
            </div>

            <!-- Inline error panel for JS-side validation errors (API rejections) -->
            <div id="transferErrorPanel" style="display:none;" class="alert alert-error"></div>

            <!-- Confirmation panel: shown after token is issued, before final submit -->
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
