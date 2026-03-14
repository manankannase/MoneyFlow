<?php
// Suppress display_errors so PHP warnings never bleed into the JSON response body
ini_set('display_errors', 0);
error_reporting(E_ALL);


define('APP_BASE', dirname(__DIR__));

require_once APP_BASE . '/utilities/security.php';
require_once APP_BASE . '/utilities/session.php';
require_once APP_BASE . '/utilities/operations.php';
require_once APP_BASE . '/utilities/validation.php';
require_once APP_BASE . '/settings/db_config.php';

applySecurityHeaders();
header('Content-Type: application/json');

$session = validateActiveSession();
if (!$session) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

// Validate CSRF
if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
    http_response_code(403);
    echo json_encode(['error' => 'CSRF validation failed.']);
    exit;
}

// Read and validate transfer parameters
$recipientId = intval($_POST['recipient_id'] ?? 0);
$amount      = round(floatval($_POST['transfer_amount'] ?? 0), 2);

if ($recipientId <= 0) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid recipient ID.']);
    exit;
}

if ($amount <= 0) {
    http_response_code(400);
    echo json_encode(['error' => 'Amount must be greater than zero.']);
    exit;
}

$amountValidation = validateMonetaryAmount($amount);
if (!$amountValidation['isValid']) {
    http_response_code(400);
    echo json_encode(['error' => $amountValidation['errorMsg']]);
    exit;
}

if ($recipientId === $session['member_id']) {
    http_response_code(400);
    echo json_encode(['error' => 'Cannot transfer funds to your own account.']);
    exit;
}

$recipient = fetchMemberProfile($recipientId);
if (!$recipient) {
    http_response_code(400);
    echo json_encode(['error' => 'Recipient account not found.']);
    exit;
}

$dbConn = getPDOConnection();

$transactionId = bin2hex(random_bytes(32)); // 64-char opaque ID
$nonce         = bin2hex(random_bytes(16)); // 32-char anti-replay nonce
$expiresAt     = date('Y-m-d H:i:s', time() + 300); // 5-minute window

$insertStmt = $dbConn->prepare(
    'INSERT INTO pending_transfers
        (transaction_id, sender_id, recipient_id, amount, nonce, expires_at)
     SELECT :txn_id, :sender_id, :recipient_id, :amount, :nonce, :expires_at
     FROM DUAL
     WHERE (
         SELECT COUNT(*) FROM pending_transfers
         WHERE sender_id = :sender_id2
           AND created_at > DATE_SUB(NOW(), INTERVAL 5 MINUTE)
     ) < 10'
);

try {
    $insertStmt->execute([
        ':txn_id'       => $transactionId,
        ':sender_id'    => $session['member_id'],
        ':sender_id2'   => $session['member_id'],
        ':recipient_id' => $recipientId,
        ':amount'       => $amount,
        ':nonce'        => $nonce,
        ':expires_at'   => $expiresAt,
    ]);
} catch (PDOException $e) {
    error_log('Failed to create pending transfer: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['error' => 'Could not initiate transfer. Please try again.']);
    exit;
}

if ($insertStmt->rowCount() === 0) {
    http_response_code(429);
    echo json_encode(['error' => 'Too many transfer requests. Please wait before trying again.']);
    exit;
}


$_SESSION['transfer_nonce'] = $transactionId;

try {
    $token = encryptTransferToken(
        $recipientId,           // stored in token for display/mismatch check only
        $amount,                // stored in token for display/mismatch check only
        $session['member_id'],  // binds token to this sender
        $transactionId,         // the DB row identifier — opaque to client
        time()
    );
} catch (RuntimeException $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Token generation failed. Please try again.']);
    exit;
}

echo json_encode([
    'success'          => true,
    'token'            => $token,
    'recipient_name'   => $recipient['account_name'], // for UI confirmation display
]);
?>
