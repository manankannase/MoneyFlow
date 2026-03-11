<?php
/**
 * Authentication Utilities
 *
 * Handles account creation and login verification using bcrypt.
 */

require_once __DIR__ . '/../settings/db_config.php';
require_once __DIR__ . '/validation.php';

/**
 * Create a new member account.
 *
 * @return array{success: bool, memberId: int|null, errorMsg: string}
 */
function createMemberAccount(string $accountId, string $email, string $password): array {
    $result = ['success' => false, 'memberId' => null, 'errorMsg' => ''];

    // Validate inputs
    if (!validateAccountName($accountId)) {
        $result['errorMsg'] = 'Invalid account name. Use 3-30 alphanumeric characters or underscores.';
        return $result;
    }
    if (!validateEmail($email)) {
        $result['errorMsg'] = 'Invalid email address.';
        return $result;
    }
    if (!validatePassword($password)) {
        $result['errorMsg'] = 'Password must be at least 8 characters with uppercase, lowercase, digit, and special character.';
        return $result;
    }

    $hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);

    try {
        $pdo  = getDbConnection();
        $stmt = $pdo->prepare(
            'INSERT INTO members (account_name, email_address, password_hash) VALUES (:account_name, :email, :hash)'
        );
        $stmt->execute([
            ':account_name' => $accountId,
            ':email'        => $email,
            ':hash'         => $hash,
        ]);
        $result['success']  = true;
        $result['memberId'] = (int) $pdo->lastInsertId();
    } catch (PDOException $e) {
        if ($e->getCode() === '23000') {
            $result['errorMsg'] = 'Account name or email already exists.';
        } else {
            error_log('MoneyFlow createMemberAccount error: ' . $e->getMessage());
            $result['errorMsg'] = 'An unexpected error occurred. Please try again.';
        }
    }

    return $result;
}

/**
 * Verify login credentials.
 *
 * Returns member data on success, or an error on failure.
 * Uses a generic error message to avoid revealing whether the
 * account name or password was wrong (timing-safe via password_verify).
 *
 * @return array{success: bool, member: array|null, errorMsg: string}
 */
function verifyLogin(string $accountId, string $password): array {
    $result = ['success' => false, 'member' => null, 'errorMsg' => ''];

    if (empty($accountId) || empty($password)) {
        $result['errorMsg'] = 'Invalid credentials.';
        return $result;
    }

    try {
        $pdo  = getDbConnection();
        $stmt = $pdo->prepare(
            'SELECT id, account_name, email_address, password_hash, account_balance, member_bio, profile_photo
             FROM members WHERE account_name = :account_name LIMIT 1'
        );
        $stmt->execute([':account_name' => $accountId]);
        $member = $stmt->fetch();

        if (!$member || !password_verify($password, $member['password_hash'])) {
            // Generic message — do not reveal whether account exists
            $result['errorMsg'] = 'Invalid credentials.';
            return $result;
        }

        // Auto-upgrade hash if bcrypt cost factor has changed
        if (password_needs_rehash($member['password_hash'], PASSWORD_BCRYPT, ['cost' => 12])) {
            $newHash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
            $upd     = $pdo->prepare('UPDATE members SET password_hash = :hash WHERE id = :id');
            $upd->execute([':hash' => $newHash, ':id' => $member['id']]);
        }

        unset($member['password_hash']);   // never expose hash outside auth layer
        $result['success'] = true;
        $result['member']  = $member;
    } catch (PDOException $e) {
        error_log('MoneyFlow verifyLogin error: ' . $e->getMessage());
        $result['errorMsg'] = 'An unexpected error occurred. Please try again.';
    }

    return $result;
}
