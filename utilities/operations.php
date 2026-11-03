<?php
/**
 * Business Operations
 *
 * Money transfers, profile updates, member search.
 * All transfers use explicit DB transactions with row-level locking.
 */

require_once __DIR__ . '/../settings/db_config.php';
require_once __DIR__ . '/validation.php';
require_once __DIR__ . '/activity_log.php';

/**
 * Transfer money from one member to another.
 *
 * Uses SELECT ... FOR UPDATE row-level locking inside a transaction to
 * prevent race conditions and double-spending.
 *
 * @return array{success: bool, errorMsg: string}
 */
function transferMoney(int $senderId, string $recipientName, mixed $amount, string $memo, string $key, string $password): array {
    $fail = fn(string $message) => ['success' => false, 'errorMsg' => $message];
    if (!validateAccountName($recipientName) || !validateAmount($amount) || !validateMemo($memo)
        || !preg_match('/^[a-f0-9]{64}$/D', $key) || !validatePassword($password)) return $fail('Invalid transfer details.');
    $minor = amountToMinor($amount);
    $decimal = minorToAmount($minor);
    $requestHash = hash('sha256', json_encode([strtolower($recipientName), $decimal, $memo], JSON_THROW_ON_ERROR));
    $pdo = getDbConnection();
    $s = $pdo->prepare('SELECT password_hash FROM members WHERE id = ?');
    $s->execute([$senderId]); $hash = $s->fetchColumn();
    if (!$hash || !password_verify($password, $hash)) return $fail('Password confirmation failed.');
    $s = $pdo->prepare('SELECT id FROM members WHERE account_name = ?');
    $s->execute([$recipientName]); $recipientId = (int)$s->fetchColumn();
    if (!$recipientId || $recipientId === $senderId) return $fail('Choose another valid recipient.');
    try {
        $pdo->beginTransaction();
        // Always lock both accounts in the same order, including opposing transfers.
        $rows = [];
        $ids = [$senderId, $recipientId]; sort($ids, SORT_NUMERIC);
        foreach ($ids as $id) {
            $s = $pdo->prepare('SELECT id, account_balance, password_hash FROM members WHERE id = ? FOR UPDATE');
            $s->execute([$id]); $row = $s->fetch();
            if (!$row) throw new RuntimeException('Account unavailable.');
            $rows[$id] = $row;
        }
        if (!hash_equals($hash, $rows[$senderId]['password_hash'])) {
            $pdo->rollBack(); return $fail('Please sign in again.');
        }
        $s = $pdo->prepare('SELECT id, request_hash FROM transfer_ledger WHERE sender_id = ? AND idempotency_key = ?');
        $s->execute([$senderId, $key]); $existing = $s->fetch();
        if ($existing) {
            $pdo->rollBack();
            return hash_equals($existing['request_hash'], $requestHash)
                ? ['success' => true, 'errorMsg' => '', 'transferId' => (int)$existing['id'], 'replayed' => true]
                : $fail('This request ID was already used for different transfer details.');
        }
        $senderMinor = amountToMinor($rows[$senderId]['account_balance']);
        $recipientMinor = amountToMinor($rows[$recipientId]['account_balance']);
        if ($senderMinor === null || $recipientMinor === null) throw new RuntimeException('Invalid balance.');
        if ($senderMinor < $minor) { $pdo->rollBack(); return $fail('Insufficient balance.'); }
        if ($recipientMinor + $minor > 999999999999) { $pdo->rollBack(); return $fail('Recipient balance limit reached.'); }
        $s = $pdo->prepare('UPDATE members SET account_balance = ? WHERE id = ?');
        $s->execute([minorToAmount($senderMinor - $minor), $senderId]);
        $s->execute([minorToAmount($recipientMinor + $minor), $recipientId]);
        $s = $pdo->prepare('INSERT INTO transfer_ledger (sender_id, recipient_id, transfer_amount, memo_text, idempotency_key, request_hash) VALUES (?, ?, ?, ?, ?, ?)');
        $s->execute([$senderId, $recipientId, $decimal, $memo, $key, $requestHash]);
        $id = (int)$pdo->lastInsertId();
        auditEvent('transfer_committed', $senderId, $pdo);
        $pdo->commit();
        return ['success' => true, 'errorMsg' => '', 'transferId' => $id, 'replayed' => false];
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        // Never silently retry an ambiguous COMMIT. The same request ID resolves it.
        error_log(json_encode(['event' => 'transfer_unconfirmed', 'type' => get_class($e)]));
        return $fail('Transfer could not be confirmed. Check history, then retry with the same request ID.');
    }
}

/**
 * Get transfer history for a member (paginated).
 *
 * @return array  List of transfer rows.
 */
function getTransferHistory(int $memberId, int $page = 1, int $perPage = 20): array {
    $page = max(1, min($page, 10000));
    $perPage = max(1, min($perPage, 50));
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
             WHERE tl.sender_id = :sender OR tl.recipient_id = :recipient
             ORDER BY tl.id DESC
             LIMIT :limit OFFSET :offset'
        );
        $stmt->bindValue(':sender', $memberId, PDO::PARAM_INT);
        $stmt->bindValue(':recipient', $memberId, PDO::PARAM_INT);
        $stmt->bindValue(':limit',  $perPage,  PDO::PARAM_INT);
        $stmt->bindValue(':offset', $offset,   PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->fetchAll();
    } catch (PDOException $e) {
        throw $e;
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
        throw $e;
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
        $pdo->beginTransaction();
        $stmt = $pdo->prepare(
            'UPDATE members SET email_address = :email, member_bio = :bio WHERE id = :id'
        );
        $stmt->execute([':email' => $email, ':bio' => $bio, ':id' => $memberId]);
        auditEvent('profile_updated', $memberId, $pdo);
        $pdo->commit();
        $result['success'] = true;
    } catch (PDOException $e) {
        if (isset($pdo) && $pdo->inTransaction()) $pdo->rollBack();
        if ($e->getCode() === '23000') {
            $result['errorMsg'] = 'Email address is already in use.';
        } else {
            throw $e;
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
    $fail = ['success' => false, 'errorMsg' => 'Use a JPEG or PNG image under 2 MB and 2048 × 2048 pixels.'];
    if (($file['error'] ?? -1) !== UPLOAD_ERR_OK || !is_string($file['tmp_name'] ?? null)
        || !is_uploaded_file($file['tmp_name']) || ($file['size'] ?? PHP_INT_MAX) > 2097152) return $fail;
    $info = @getimagesize($file['tmp_name']);
    if (!$info || $info[0] > 2048 || $info[1] > 2048 || !in_array($info[2], [IMAGETYPE_JPEG, IMAGETYPE_PNG], true)) return $fail;
    $image = $info[2] === IMAGETYPE_JPEG ? @imagecreatefromjpeg($file['tmp_name']) : @imagecreatefrompng($file['tmp_name']);
    if (!$image) return $fail;
    $filename = bin2hex(random_bytes(32)) . '.png';
    $path = '/var/lib/moneyflow/avatars/' . $filename;
    try {
        if (!imagepng($image, $path)) throw new RuntimeException('Avatar storage unavailable.');
        $pdo = getDbConnection(); $pdo->beginTransaction();
        $s = $pdo->prepare('SELECT profile_photo FROM members WHERE id = ? FOR UPDATE');
        $s->execute([$memberId]); $old = $s->fetchColumn();
        $s = $pdo->prepare('UPDATE members SET profile_photo = ? WHERE id = ?');
        $s->execute([$filename, $memberId]);
        auditEvent('avatar_updated', $memberId, $pdo);
        $pdo->commit();
        if (is_string($old) && preg_match('/^[a-f0-9]{64}\.png$/D', $old)) @unlink('/var/lib/moneyflow/avatars/' . $old);
        return ['success' => true, 'errorMsg' => ''];
    } catch (Throwable $e) {
        if (isset($pdo) && $pdo->inTransaction()) $pdo->rollBack();
        @unlink($path); throw $e;
    } finally { imagedestroy($image); }
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
