<?php
/**
 * Business Operations
 *
 * Money transfers, profile updates, member search.
 * All transfers use explicit DB transactions with row-level locking.
 */

require_once __DIR__ . '/../settings/db_config.php';
require_once __DIR__ . '/validation.php';

/**
 * Transfer money from one member to another.
 *
 * Uses SELECT ... FOR UPDATE row-level locking inside a transaction to
 * prevent race conditions and double-spending.
 *
 * @return array{success: bool, errorMsg: string}
 */
function transferMoney(int $senderId, string $recipientName, mixed $amount, string $memo): array {
    $result = ['success' => false, 'errorMsg' => ''];

    if (!validateAmount($amount)) {
        $result['errorMsg'] = 'Invalid transfer amount.';
        return $result;
    }
    if (!validateMemo($memo)) {
        $result['errorMsg'] = 'Memo is too long (max 500 characters).';
        return $result;
    }

    $amount = round((float) $amount, 2);

    try {
        $pdo = getDbConnection();
        $pdo->beginTransaction();

        // Lock sender row for update
        $senderStmt = $pdo->prepare(
            'SELECT id, account_name, account_balance FROM members WHERE id = :id FOR UPDATE'
        );
        $senderStmt->execute([':id' => $senderId]);
        $sender = $senderStmt->fetch();

        if (!$sender) {
            $pdo->rollBack();
            $result['errorMsg'] = 'Sender account not found.';
            return $result;
        }

        // Lock recipient row for update
        $recipientStmt = $pdo->prepare(
            'SELECT id, account_name FROM members WHERE account_name = :account_name FOR UPDATE'
        );
        $recipientStmt->execute([':account_name' => $recipientName]);
        $recipient = $recipientStmt->fetch();

        if (!$recipient) {
            $pdo->rollBack();
            $result['errorMsg'] = 'Recipient account not found.';
            return $result;
        }

        // Prevent self-transfers
        if ($sender['id'] === $recipient['id']) {
            $pdo->rollBack();
            $result['errorMsg'] = 'You cannot transfer money to yourself.';
            return $result;
        }

        // Check sufficient balance
        if ((float) $sender['account_balance'] < $amount) {
            $pdo->rollBack();
            $result['errorMsg'] = 'Insufficient balance.';
            return $result;
        }

        // Debit sender
        $debitStmt = $pdo->prepare(
            'UPDATE members SET account_balance = account_balance - :amount WHERE id = :id'
        );
        $debitStmt->execute([':amount' => $amount, ':id' => $sender['id']]);

        // Credit recipient
        $creditStmt = $pdo->prepare(
            'UPDATE members SET account_balance = account_balance + :amount WHERE id = :id'
        );
        $creditStmt->execute([':amount' => $amount, ':id' => $recipient['id']]);

        // Record in ledger
        $ledgerStmt = $pdo->prepare(
            'INSERT INTO transfer_ledger (sender_id, recipient_id, transfer_amount, memo_text)
             VALUES (:sender_id, :recipient_id, :amount, :memo)'
        );
        $ledgerStmt->execute([
            ':sender_id'    => $sender['id'],
            ':recipient_id' => $recipient['id'],
            ':amount'       => $amount,
            ':memo'         => $memo,
        ]);

        $pdo->commit();
        $result['success'] = true;
    } catch (PDOException $e) {
        if (isset($pdo) && $pdo->inTransaction()) {
            $pdo->rollBack();
        }
        error_log('MoneyFlow transferMoney error: ' . $e->getMessage());
        $result['errorMsg'] = 'Transfer failed due to a system error. Please try again.';
    }

    return $result;
}

/**
 * Get transfer history for a member (paginated).
 *
 * @return array  List of transfer rows.
 */
function getTransferHistory(int $memberId, int $page = 1, int $perPage = 20): array {
    $offset = ($page - 1) * $perPage;

    try {
        $pdo  = getDbConnection();
        $stmt = $pdo->prepare(
            'SELECT tl.id, tl.transfer_amount, tl.memo_text, tl.created_at,
                    sender.account_name AS sender_name,
                    recipient.account_name AS recipient_name
             FROM transfer_ledger tl
             JOIN members sender   ON sender.id   = tl.sender_id
             JOIN members recipient ON recipient.id = tl.recipient_id
             WHERE tl.sender_id = :id OR tl.recipient_id = :id
             ORDER BY tl.created_at DESC
             LIMIT :limit OFFSET :offset'
        );
        $stmt->bindValue(':id',     $memberId, PDO::PARAM_INT);
        $stmt->bindValue(':limit',  $perPage,  PDO::PARAM_INT);
        $stmt->bindValue(':offset', $offset,   PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->fetchAll();
    } catch (PDOException $e) {
        error_log('MoneyFlow getTransferHistory error: ' . $e->getMessage());
        return [];
    }
}

/**
 * Search for members by account name (partial match, excluding self).
 *
 * @return array  List of matching member rows.
 */
function searchMembers(string $query, int $excludeId, int $limit = 20): array {
    if (empty($query) || strlen($query) > 50) {
        return [];
    }

    try {
        $pdo  = getDbConnection();
        $stmt = $pdo->prepare(
            'SELECT id, account_name, member_bio, profile_photo
             FROM members
             WHERE account_name LIKE :query AND id != :exclude_id
             ORDER BY account_name
             LIMIT :limit'
        );
        $stmt->bindValue(':query',      '%' . $query . '%', PDO::PARAM_STR);
        $stmt->bindValue(':exclude_id', $excludeId,         PDO::PARAM_INT);
        $stmt->bindValue(':limit',      $limit,             PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->fetchAll();
    } catch (PDOException $e) {
        error_log('MoneyFlow searchMembers error: ' . $e->getMessage());
        return [];
    }
}

/**
 * Update a member's profile (bio and email).
 *
 * @return array{success: bool, errorMsg: string}
 */
function updateProfile(int $memberId, string $bio, string $email): array {
    $result = ['success' => false, 'errorMsg' => ''];

    if (!validateEmail($email)) {
        $result['errorMsg'] = 'Invalid email address.';
        return $result;
    }
    if (strlen($bio) > 500) {
        $result['errorMsg'] = 'Bio must not exceed 500 characters.';
        return $result;
    }

    try {
        $pdo  = getDbConnection();
        $stmt = $pdo->prepare(
            'UPDATE members SET email_address = :email, member_bio = :bio WHERE id = :id'
        );
        $stmt->execute([':email' => $email, ':bio' => $bio, ':id' => $memberId]);
        $result['success'] = true;
    } catch (PDOException $e) {
        if ($e->getCode() === '23000') {
            $result['errorMsg'] = 'Email address is already in use.';
        } else {
            error_log('MoneyFlow updateProfile error: ' . $e->getMessage());
            $result['errorMsg'] = 'Profile update failed. Please try again.';
        }
    }

    return $result;
}

/**
 * Save an uploaded avatar and update the member record.
 *
 * @param  array $file    Element from $_FILES
 * @return array{success: bool, errorMsg: string}
 */
function saveAvatar(int $memberId, array $file): array {
    require_once __DIR__ . '/validation.php';

    $validation = validateAvatarUpload($file);
    if (!$validation['valid']) {
        return ['success' => false, 'errorMsg' => $validation['errorMsg']];
    }

    $ext      = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    $filename = 'avatar_' . $memberId . '_' . bin2hex(random_bytes(8)) . '.' . $ext;
    $destDir  = __DIR__ . '/../webroot/uploads/avatars/';
    $destPath = $destDir . $filename;

    if (!move_uploaded_file($file['tmp_name'], $destPath)) {
        return ['success' => false, 'errorMsg' => 'Failed to save the uploaded file.'];
    }

    try {
        $pdo  = getDbConnection();
        $stmt = $pdo->prepare('UPDATE members SET profile_photo = :photo WHERE id = :id');
        $stmt->execute([':photo' => $filename, ':id' => $memberId]);
        return ['success' => true, 'errorMsg' => ''];
    } catch (PDOException $e) {
        error_log('MoneyFlow saveAvatar error: ' . $e->getMessage());
        return ['success' => false, 'errorMsg' => 'Failed to update profile photo.'];
    }
}

/**
 * Get a single member's public profile by account name.
 *
 * @return array|null
 */
function getMemberProfile(string $accountName): ?array {
    try {
        $pdo  = getDbConnection();
        $stmt = $pdo->prepare(
            'SELECT id, account_name, member_bio, profile_photo, created_at
             FROM members WHERE account_name = :account_name LIMIT 1'
        );
        $stmt->execute([':account_name' => $accountName]);
        $row = $stmt->fetch();
        return $row ?: null;
    } catch (PDOException $e) {
        error_log('MoneyFlow getMemberProfile error: ' . $e->getMessage());
        return null;
    }
}
