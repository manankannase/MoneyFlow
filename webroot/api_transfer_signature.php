<?php
// Suppress display_errors so PHP warnings never bleed into the JSON response body
ini_set('display_errors', 0);
error_reporting(E_ALL);

/**
 * API Endpoint: Create Pending Transfer (DB Intent Binding)
 *
 * Industry-standard defense against proxy tampering (Burp Suite, MITM):
 *
 * OLD approach (vulnerable):
 *   Client sends recipient + amount → server encrypts them → client sends blob back.
 *   Attacker intercepts THIS request, changes recipient/amount → server issues a valid
 *   token for the tampered values → transfer executes with attacker's values.
 *
 * NEW approach (DB intent binding):
 *   Client sends recipient + amount → server validates and writes a pending_transfers
 *   row in the database → returns only an opaque transaction_id to the client.
 *   At execution, server looks up the transaction_id in the DB and uses ONLY the
 *   DB-stored values. The client never sends recipient or amount again.
 *
 *   What can Burp tamper with?
 *     - The transaction_id → a random UUID, changing it fails the DB lookup or
 *       points to a different sender's record (sender_id check rejects it).
 *     - Nothing else — recipient and amount are not in the final POST at all.
 *
 *   The AES-256-GCM token is still used as an additional layer: the transaction_id
 *   is encrypted inside the token, so it cannot be swapped for another user's ID.
 */

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
$recipientIdRaw = $_POST['recipient_id'] ?? 0;
$amountRaw      = $_POST['transfer_amount'] ?? 0;
if (!is_string($recipientIdRaw) && !is_int($recipientIdRaw)) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid recipient ID format.']);
    exit;
}
if (!is_string($amountRaw) && !is_int($amountRaw) && !is_float($amountRaw)) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid amount format.']);
    exit;
}
$recipientId = intval($recipientIdRaw);

if ($recipientId <= 0) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid recipient ID.']);
    exit;
}

// Validate the raw string BEFORE floatval() — floatval('1e1') silently becomes 10.0,
// which would then pass the plain-decimal regex in validateMonetaryAmount.
$amountValidation = validateMonetaryAmount($amountRaw);
if (!$amountValidation['isValid']) {
    http_response_code(400);
    echo json_encode(['error' => $amountValidation['errorMsg']]);
    exit;
}

// Safe to convert now — raw string has passed the plain-decimal allowlist check.
$amount = round(floatval($amountRaw), 2);

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

// -----------------------------------------------------------------------
// SECURITY FIX A2: Rate limit pending transfer creation (max 10 per 5 min per user).
// The check and insert are atomic — a single INSERT ... SELECT statement reads
// the count and inserts in one operation, eliminating the TOCTOU race where
// concurrent requests could all pass a separate COUNT check and each insert.
// rowCount() === 0 means the WHERE subquery saw >= 10 rows and blocked the insert.
// -----------------------------------------------------------------------
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

// rowCount() === 0 means the rate limit subquery blocked the insert
if ($insertStmt->rowCount() === 0) {
    http_response_code(429);
    echo json_encode(['error' => 'Too many transfer requests. Please wait before trying again.']);
    exit;
}

// Store the transaction_id in session — this is what the token's nonce field carries,
// so the check in transfer.php (hash_equals session vs token nonce) will match correctly.
// The DB 'used' flag is the primary anti-replay guard; this is a secondary session guard.
$_SESSION['transfer_nonce'] = $transactionId;

// Wrap the transaction_id in an AES-256-GCM token so the client cannot swap
// one user's transaction_id for another's. The token binds txn_id to sender_id.
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
