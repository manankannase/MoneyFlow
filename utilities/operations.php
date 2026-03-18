<?php
/**
 * Core Business Logic and Transaction Processing
 *
 * Handles member lookup, fund transfer operations, and profile management.
 */

require_once __DIR__ . '/../settings/db_config.php';
require_once __DIR__ . '/validation.php';

/**
 * Retrieve member profile by ID.
 *
 * @param int $memberId Member ID
 * @return array|null Member details or null if not found
 */
function fetchMemberProfile(int $memberId): ?array {
    $dbConn = getPDOConnection();

    $query = $dbConn->prepare(
        'SELECT id, account_name, email_address, account_balance, member_bio, profile_photo, 
                created_at, updated_at
         FROM members WHERE id = :id LIMIT 1'
    );

    $query->execute([':id' => $memberId]);
    $profile = $query->fetch();

    return $profile ?: null;
}

/**
 * Search members by account ID or member ID.
 * Presents basic directory functionality.
 *
 * @param string $searchTerm Search query (username or ID)
 * @param int    $maxResults Maximum results
 * @return array List of matching members
 */
function discoverMembers(string $searchTerm, int $maxResults = 20): array {
    $dbConn = getPDOConnection();

    // Check if search term is numeric
    if (ctype_digit($searchTerm)) {
        $query = $dbConn->prepare(
            'SELECT id, account_name, profile_photo
             FROM members WHERE id = :id LIMIT 1'
        );
        $query->execute([':id' => (int) $searchTerm]);
        $result = $query->fetch();
        return $result ? [$result] : [];
    }

    // Search by account name (partial match)
    $query = $dbConn->prepare(
        'SELECT id, account_name, profile_photo
         FROM members WHERE account_name LIKE :search_term
         ORDER BY account_name ASC LIMIT :max_results'
    );

    // Escape LIKE wildcards to prevent wildcard injection
    $escapedTerm = str_replace(['%', '_'], ['\\%', '\\_'], $searchTerm);

    $query->bindValue(':search_term', '%' . $escapedTerm . '%', PDO::PARAM_STR);
    $query->bindValue(':max_results', $maxResults, PDO::PARAM_INT);
    $query->execute();

    return $query->fetchAll();
}

/**
 * Execute fund transfer between two members.
 * Uses database transactions and row-level locking to maintain consistency.
 *
 * SECURITY: This function ALWAYS uses the authenticated sender ID passed to it.
 * The caller MUST ensure that $senderMemberId comes from the session, not from user input.
 *
 * @param int    $senderMemberId Sender's ID (must come from authenticated session)
 * @param int    $recipientMemberId Recipient's ID
 * @param float  $transferAmount Amount to transfer
 * @param string $memo Optional transaction memo
 * @return array ['success' => bool, 'errorMsg' => string|null]
 */
function executeMoneyTransfer(int $senderMemberId, int $recipientMemberId, float $transferAmount, string $memo = ''): array {
    // Normalize to exactly 2 decimal places immediately — eliminates PHP float drift.
    // All actual balance arithmetic runs inside MySQL on DECIMAL(12,2) columns, so
    // PHP only performs comparisons. round(..., 2) is sufficient; no bcmath needed.
    $transferAmount = round($transferAmount, 2);

    // Validate sender and recipient are different
    if ($senderMemberId === $recipientMemberId) {
        return ['success' => false, 'errorMsg' => 'Cannot transfer funds to your own account.'];
    }

    // Validate amount
    if ($transferAmount <= 0) {
        return ['success' => false, 'errorMsg' => 'Transfer amount must exceed zero.'];
    }

    // Fetch sender balance and verify account exists before any other check.
    // This ensures "Insufficient balance" always wins over velocity messages
    // when the fundamental problem is simply not having enough funds.
    $dbConn = getPDOConnection();
    $senderCheckQuery = $dbConn->prepare(
        'SELECT id, account_balance FROM members WHERE id = :id LIMIT 1'
    );
    $senderCheckQuery->execute([':id' => $senderMemberId]);
    $senderPreCheck = $senderCheckQuery->fetch();
    if (!$senderPreCheck) {
        return ['success' => false, 'errorMsg' => 'Sender account not found.'];
    }
    $currentBalance = round((float)$senderPreCheck['account_balance'], 2);
    if ($transferAmount > $currentBalance) {
        return ['success' => false, 'errorMsg' => 'Insufficient account balance.'];
    }

    // SECURITY FIX A3: Daily transfer velocity check
    // Max 10 transfers per day and max ₹5000 daily outflow
    $velocityQuery = $dbConn->prepare(
        'SELECT COUNT(*) as daily_count, COALESCE(SUM(transfer_amount), 0) as daily_total
         FROM transfer_ledger
         WHERE sender_id = :sender_id
           AND created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)'
    );
    $velocityQuery->execute([':sender_id' => $senderMemberId]);
    $velocityResult = $velocityQuery->fetch();

    if ((int)$velocityResult['daily_count'] >= 10) {
        return ['success' => false, 'errorMsg' => 'Daily transfer limit reached (max 10 transfers per day). Please try again tomorrow.'];
    }
    $dailySent      = round((float)$velocityResult['daily_total'], 2);
    $dailyRemaining = round(5000 - $dailySent, 2);
    if ($dailySent + $transferAmount > 5000) {
        // Cap reported remaining at actual balance so the figure is always achievable
        $effectiveRemaining = min($dailyRemaining, $currentBalance);
        if ($effectiveRemaining <= 0) {
            $errorMsg = 'Daily outflow limit of ₹5,000 reached. Please try again tomorrow.';
        } else {
            $errorMsg = 'Daily outflow limit of ₹5,000 would be exceeded. '
                      . 'You can send up to ₹' . number_format($effectiveRemaining, 2) . ' more today.';
        }
        return ['success' => false, 'errorMsg' => $errorMsg];
    }

    try {
        // START TRANSACTION: Use FOR UPDATE locks for row-level consistency
        $dbConn->beginTransaction();

        // Lock both rows in ascending ID order to prevent bidirectional deadlocks.
        // If A→B and B→A run simultaneously without consistent ordering, each
        // transaction acquires one lock and waits for the other — classic deadlock.
        // Always locking the lower ID first serialises both directions identically.
        $firstId  = min($senderMemberId, $recipientMemberId);
        $secondId = max($senderMemberId, $recipientMemberId);

        $lockQuery = $dbConn->prepare(
            'SELECT id, account_balance FROM members WHERE id = :id FOR UPDATE'
        );

        $lockQuery->execute([':id' => $firstId]);
        $firstRecord = $lockQuery->fetch();

        $lockQuery->execute([':id' => $secondId]);
        $secondRecord = $lockQuery->fetch();

        // Map back to sender / recipient regardless of lock order
        $senderRecord    = ($firstId === $senderMemberId)    ? $firstRecord  : $secondRecord;
        $recipientRecord = ($firstId === $recipientMemberId) ? $firstRecord  : $secondRecord;

        if (!$senderRecord) {
            $dbConn->rollBack();
            return ['success' => false, 'errorMsg' => 'Sender account not found.'];
        }

        if (round((float) $senderRecord['account_balance'], 2) < $transferAmount) {
            $dbConn->rollBack();
            return ['success' => false, 'errorMsg' => 'Insufficient account balance.'];
        }

        if (!$recipientRecord) {
            $dbConn->rollBack();
            return ['success' => false, 'errorMsg' => 'Recipient account not found.'];
        }

        // Deduct from sender
        $debitQuery = $dbConn->prepare(
            'UPDATE members SET account_balance = account_balance - :amount WHERE id = :id'
        );
        $debitQuery->execute([':amount' => $transferAmount, ':id' => $senderMemberId]);

        // Credit to recipient
        $creditQuery = $dbConn->prepare(
            'UPDATE members SET account_balance = account_balance + :amount WHERE id = :id'
        );
        $creditQuery->execute([':amount' => $transferAmount, ':id' => $recipientMemberId]);

        // Record transfer in ledger
        $ledgerQuery = $dbConn->prepare(
            'INSERT INTO transfer_ledger (sender_id, recipient_id, transfer_amount, memo_text)
             VALUES (:sender_id, :recipient_id, :amount, :memo_text)'
        );
        $ledgerQuery->execute([
            ':sender_id'     => $senderMemberId,
            ':recipient_id'  => $recipientMemberId,
            ':amount'        => $transferAmount,
            ':memo_text'     => $memo,
        ]);

        // COMMIT TRANSACTION
        $dbConn->commit();

        return ['success' => true, 'errorMsg' => null];

    } catch (PDOException $e) {
        // ROLLBACK on any database error
        $dbConn->rollBack();
        error_log('Transfer execution failed: ' . $e->getMessage());
        return ['success' => false, 'errorMsg' => 'Transaction failed. Please try again.'];
    }
}

/**
 * Retrieve transfer history for a member.
 * Shows all transfers received and sent.
 *
 * @param int $memberId Member ID
 * @param int $pageNum Page number for pagination
 * @param int $itemsPerPage Items per page
 * @return array Transfer records
 */
function retrieveMemberTransferHistory(int $memberId, int $pageNum = 1, int $itemsPerPage = 25): array {
    $offset = ($pageNum - 1) * $itemsPerPage;
    $dbConn = getPDOConnection();

    $query = $dbConn->prepare(
        'SELECT tl.id, tl.sender_id, tl.recipient_id, tl.transfer_amount, tl.memo_text, 
                tl.created_at,
                s.account_name as sender_name, r.account_name as recipient_name
         FROM transfer_ledger tl
         LEFT JOIN members s ON tl.sender_id = s.id
         LEFT JOIN members r ON tl.recipient_id = r.id
         WHERE tl.sender_id = ? OR tl.recipient_id = ?
         ORDER BY tl.created_at DESC
         LIMIT ? OFFSET ?'
    );

    $query->bindValue(1, $memberId, PDO::PARAM_INT);
    $query->bindValue(2, $memberId, PDO::PARAM_INT);
    $query->bindValue(3, $itemsPerPage, PDO::PARAM_INT);
    $query->bindValue(4, $offset, PDO::PARAM_INT);
    $query->execute();

    return $query->fetchAll();
}

/**
 * Count total transfers for a member.
 *
 * @param int $memberId Member ID
 * @return int Total transfer count
 */
function countMemberTransfers(int $memberId): int {
    $dbConn = getPDOConnection();

    $query = $dbConn->prepare(
        'SELECT COUNT(*) as total_transfers
         FROM transfer_ledger
         WHERE sender_id = ? OR recipient_id = ?'
    );

    $query->execute([$memberId, $memberId]);
    $result = $query->fetch();

    return (int) ($result['total_transfers'] ?? 0);
}

/**
 * Update member profile information.
 *
 * @param int    $memberId Member ID
 * @param array  $profileData Updated profile data
 * @return array ['success' => bool, 'errorMsg' => string|null]
 */
function modifyMemberProfile(int $memberId, array $profileData): array {
    if (empty($profileData)) {
        return ['success' => false, 'errorMsg' => 'No data to update.'];
    }

    $dbConn = getPDOConnection();
    $updateFields = [];
    $bindParams = [':member_id' => $memberId];

    // Handle bio update
    if (isset($profileData['bio'])) {
        $sanitizedBio = sanitizeBioText($profileData['bio']);
        $updateFields[] = 'member_bio = :bio';
        $bindParams[':bio'] = $sanitizedBio;
    }

    if (empty($updateFields)) {
        return ['success' => false, 'errorMsg' => 'No valid fields to update.'];
    }

    $updateFields[] = 'updated_at = NOW()';
    $sqlQuery = 'UPDATE members SET ' . implode(', ', $updateFields) . ' WHERE id = :member_id';

    try {
        $updateQuery = $dbConn->prepare($sqlQuery);
        $updateQuery->execute($bindParams);

        return ['success' => true, 'errorMsg' => null];
    } catch (PDOException $e) {
        error_log('Profile update failed: ' . $e->getMessage());
        return ['success' => false, 'errorMsg' => 'Profile update failed.'];
    }
}

/**
 * Handle profile photo upload.
 *
 * @param int   $memberId Member ID
 * @param array $uploadedFile $_FILES array element
 * @return array ['success' => bool, 'errorMsg' => string|null]
 */
function updateProfilePhoto(int $memberId, array $uploadedFile): array {
    // Rate limit: max 10 avatar uploads per member per hour.
    // Atomic INSERT ... SELECT prevents TOCTOU races.
    $dbConn = getPDOConnection();
    $rateLimitStmt = $dbConn->prepare(
        'INSERT INTO avatar_upload_attempts (member_id)
         SELECT :mid FROM DUAL
         WHERE (
             SELECT COUNT(*) FROM avatar_upload_attempts
             WHERE member_id = :mid2
               AND uploaded_at > DATE_SUB(NOW(), INTERVAL 1 HOUR)
         ) < 10'
    );
    $rateLimitStmt->execute([':mid' => $memberId, ':mid2' => $memberId]);
    if ($rateLimitStmt->rowCount() === 0) {
        return ['success' => false, 'errorMsg' => 'Too many avatar uploads. Please wait before trying again.'];
    }

    // Validate upload (checks MIME type via finfo from actual file bytes)
    $validation = validateAvatarUpload($uploadedFile);
    if (!$validation['isValid']) {
        return ['success' => false, 'errorMsg' => $validation['errorMsg']];
    }

    // -----------------------------------------------------------------------
    // FIX V2: Extension MUST come from the validated MIME type map only.
    // We NEVER use pathinfo($uploadedFile['name'], ...) — that reads the
    // attacker-controlled original filename. A file named "shell.php" that
    // starts with GIF89a bytes would pass the MIME check but be executed
    // as PHP by Apache if its extension were preserved.
    // -----------------------------------------------------------------------
    $mimeToExt = [
        'image/jpeg' => 'jpg',
        'image/png'  => 'png',
        'image/gif'  => 'gif',
        'image/webp' => 'webp',
    ];

    $finfo    = finfo_open(FILEINFO_MIME_TYPE);
    $mimeType = finfo_file($finfo, $uploadedFile['tmp_name']);
    finfo_close($finfo);

    $safeExt = $mimeToExt[$mimeType] ?? null;
    if ($safeExt === null) {
        return ['success' => false, 'errorMsg' => 'Unsupported image type after re-check.'];
    }

    // FIX V2: Completely random filename — zero bytes from attacker input
    $uniqueFilename = 'avatar_' . bin2hex(random_bytes(16)) . '.' . $safeExt;
    $uploadDir  = dirname(__DIR__) . '/webroot/uploads/avatars/';
    $uploadPath = $uploadDir . $uniqueFilename;

    // Create directory if not exists
    if (!is_dir($uploadDir) && !mkdir($uploadDir, 0755, true) && !is_dir($uploadDir)) {
        return ['success' => false, 'errorMsg' => 'Upload directory could not be created.'];
    }

    // FIX V2 (defence-in-depth): Ensure .htaccess disabling PHP exists in the avatars dir.
    // Even if a PHP file somehow slipped through, Apache would not execute it.
    $htaccessPath = $uploadDir . '.htaccess';
    if (!file_exists($htaccessPath)) {
        file_put_contents(
            $htaccessPath,
            "php_flag engine off
Options -ExecCGI
AddType text/plain .php .php3 .php4 .php5 .phtml .phar
"
        );
    }

    // Move uploaded file
    if (!move_uploaded_file($uploadedFile['tmp_name'], $uploadPath)) {
        return ['success' => false, 'errorMsg' => 'File upload failed.'];
    }

    // SECURITY FIX: Re-encode image using GD to strip ALL embedded payloads
    // This destroys any PHP code, EXIF exploits, or polyglot data hidden in the image
    $reEncodedPath = $uploadDir . 'clean_' . bin2hex(random_bytes(16)) . '.' . $safeExt;
    $reEncodeSuccess = false;

    switch ($mimeType) {
        case 'image/jpeg':
            $img = @imagecreatefromjpeg($uploadPath);
            if ($img !== false) {
                $reEncodeSuccess = imagejpeg($img, $reEncodedPath, 85);
                imagedestroy($img);
            }
            break;
        case 'image/png':
            $img = @imagecreatefrompng($uploadPath);
            if ($img !== false) {
                imagesavealpha($img, true);
                $reEncodeSuccess = imagepng($img, $reEncodedPath, 6);
                imagedestroy($img);
            }
            break;
        case 'image/gif':
            $img = @imagecreatefromgif($uploadPath);
            if ($img !== false) {
                $reEncodeSuccess = imagegif($img, $reEncodedPath);
                imagedestroy($img);
            }
            break;
        case 'image/webp':
            $img = @imagecreatefromwebp($uploadPath);
            if ($img !== false) {
                $reEncodeSuccess = imagewebp($img, $reEncodedPath, 80);
                imagedestroy($img);
            }
            break;
    }

    // Remove the original uploaded file
    @unlink($uploadPath);

    if (!$reEncodeSuccess) {
        @unlink($reEncodedPath);
        return ['success' => false, 'errorMsg' => 'Image processing failed. The file may be corrupted.'];
    }

    // Use the re-encoded file as the final avatar
    $finalFilename = basename($reEncodedPath);

    // Delete the old avatar file from disk before updating the DB record.
    // Without this, every upload permanently grows the uploads directory.
    $oldPhotoQuery = $dbConn->prepare('SELECT profile_photo FROM members WHERE id = :id');
    $oldPhotoQuery->execute([':id' => $memberId]);
    $oldRecord = $oldPhotoQuery->fetch();
    if ($oldRecord && $oldRecord['profile_photo']) {
        $oldPath = dirname(__DIR__) . '/webroot' . $oldRecord['profile_photo'];
        if (file_exists($oldPath) && str_contains($oldPath, '/uploads/avatars/')) {
            @unlink($oldPath);
        }
    }

    // Update database
    $updateQuery = $dbConn->prepare(
        'UPDATE members SET profile_photo = :photo_path, updated_at = NOW() WHERE id = :id'
    );

    try {
        $updateQuery->execute([
            ':photo_path' => '/uploads/avatars/' . $finalFilename,
            ':id'         => $memberId
        ]);

        return ['success' => true, 'errorMsg' => null];
    } catch (PDOException $e) {
        error_log('Profile photo database update failed: ' . $e->getMessage());
        return ['success' => false, 'errorMsg' => 'Profile update failed.'];
    }
}
?>
