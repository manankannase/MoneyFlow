<?php
/**
 * Transfer Page
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

$error     = '';
$success   = '';
$pageTitle = 'Transfer Money';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // CSRF validation
    $csrfToken = $_POST['csrf_token'] ?? '';
    if (!validateCsrfToken($csrfToken, $session['csrf_token'])) {
        http_response_code(403); $error = 'Invalid request. Please try again.';
    } elseif (!consumeRateLimit('transfer', (string)$session['member_id'], 10, 60)) {
        http_response_code(429); $error = 'Too many transfer attempts.';
    } else {
        $recipient = trim($_POST['recipient'] ?? '');
        $amount    = $_POST['amount'] ?? '';
        $memo      = trim($_POST['memo'] ?? '');

        $result = transferMoney(
            (int) $session['member_id'],
            $recipient,
            $amount,
            $memo,
            $_POST['request_id'] ?? '',
            $_POST['password'] ?? ''
        );

        if ($result['success']) {
            $success = 'Transfer recorded. Reference: ' . $result['transferId'];
            // Refresh session data to get updated balance
            $session = validateSession();
        } else {
            $error = $result['errorMsg'];
        }
    }
}

$requestId = $_POST['request_id'] ?? bin2hex(random_bytes(32));
if (!preg_match('/^[a-f0-9]{64}$/D', $requestId)) $requestId = bin2hex(random_bytes(32));
if ($success) $requestId = bin2hex(random_bytes(32));
require_once __DIR__ . '/../layouts/header.php';
?>
<div class="transfer-container">
    <h1>Send Money</h1>
    <?php if ($error): ?>
        <div class="alert alert-error"><?= h($error) ?></div>
    <?php endif; ?>
    <?php if ($success): ?>
        <div class="alert alert-success"><?= h($success) ?></div>
    <?php endif; ?>
    <div class="balance-info">
        Available Balance: <strong>₹<?= h(number_format((float)$session['account_balance'], 2)) ?></strong>
    </div>
    <form method="post" action="/transfer.php" class="transfer-form">
        <input type="hidden" name="request_id" value="<?= h($requestId) ?>">
        <input type="hidden" name="csrf_token" value="<?= h($session['csrf_token']) ?>">
        <div class="form-group">
            <label for="recipient">Recipient Username</label>
            <input type="text" id="recipient" name="recipient"
                   required maxlength="30" autocomplete="off"
                   pattern="[a-zA-Z0-9_]{3,30}"
                   value="<?= h($_POST['recipient'] ?? '') ?>">
        </div>
        <div class="form-group">
            <label for="amount">Amount (₹)</label>
            <input type="number" id="amount" name="amount"
                   required min="0.01" max="999999.99" step="0.01"
                   value="<?= h($_POST['amount'] ?? '') ?>">
        </div>
        <div class="form-group">
            <label for="memo">Memo (optional)</label>
            <textarea id="memo" name="memo" maxlength="500" rows="3"><?= h($_POST['memo'] ?? '') ?></textarea>
        </div>
        <div class="form-group"><label for="password">Confirm your password</label><input type="password" id="password" name="password" required maxlength="72" autocomplete="current-password"></div>
        <button type="submit" class="btn btn-primary">Send Money</button>
    </form>
</div>
<?php require_once __DIR__ . '/../layouts/footer.php'; ?>
