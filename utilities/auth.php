<?php
declare(strict_types=1);
require_once __DIR__ . '/validation.php';
require_once __DIR__ . '/activity_log.php';

function createMemberAccount(string $accountId, string $email, string $password): array {
    $result = ['success' => false, 'memberId' => null, 'errorMsg' => 'Account could not be created.'];
    if (!validateAccountName($accountId) || !validateEmail($email) || !validatePassword($password)) return $result;
    $pdo = getDbConnection();
    try {
        $pdo->beginTransaction();
        $s = $pdo->prepare('INSERT INTO members (account_name, email_address, password_hash) VALUES (?, ?, ?)');
        $s->execute([$accountId, $email, password_hash($password, PASSWORD_BCRYPT, ['cost' => 12])]);
        $id = (int)$pdo->lastInsertId();
        auditEvent('account_created', $id, $pdo);
        $pdo->commit();
        return ['success' => true, 'memberId' => $id, 'errorMsg' => ''];
    } catch (PDOException $e) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        if ($e->getCode() !== '23000') throw $e;
        return $result;
    }
}

function verifyLogin(string $accountId, string $password): array {
    $result = ['success' => false, 'member' => null, 'errorMsg' => 'Invalid credentials.'];
    $pdo = getDbConnection();
    $s = $pdo->prepare('SELECT id, password_hash FROM members WHERE account_name = ?');
    $s->execute([substr($accountId, 0, 30)]);
    $member = $s->fetch();
    // A fixed valid bcrypt hash keeps nonexistent-user failures on the hashing path.
    $dummy = '$2y$12$IjDTNNNsKbHveWnTgCiNVuD3zblzwYqpdrJ/1sEkmV9YRhZlDQJ8S';
    $valid = password_verify(str_contains($password, "\0") ? '' : substr($password, 0, 72), $member['password_hash'] ?? $dummy);
    if (!$member || !$valid || !validateAccountName($accountId) || strlen($password) > 72 || str_contains($password, "\0")) {
        auditEvent('login_failed'); return $result;
    }
    $pdo->beginTransaction();
    try {
        $s = $pdo->prepare('SELECT password_hash FROM members WHERE id = ? FOR UPDATE');
        $s->execute([$member['id']]);
        if (!hash_equals($member['password_hash'], (string)$s->fetchColumn())) {
            $pdo->rollBack(); return $result;
        }
        if (password_needs_rehash($member['password_hash'], PASSWORD_BCRYPT, ['cost' => 12])) {
            $s = $pdo->prepare('UPDATE members SET password_hash = ? WHERE id = ?');
            $s->execute([password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]), $member['id']]);
        }
        auditEvent('login_succeeded', (int)$member['id'], $pdo);
        $pdo->commit();
        return ['success' => true, 'member' => ['id' => (int)$member['id']], 'errorMsg' => ''];
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        throw $e;
    }
}
