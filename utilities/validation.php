<?php
/**
 * Data Validation and Output Sanitization Module
 *
 * Enforces strict validation on all user-provided input.
 * This module provides comprehensive validation for all input types and contexts.
 *
 * Core Principles:
 * - Apply strict type and format validation on all inputs
 * - Implement positive allowlists (not negative blocklists)
 * - Sanitize output based on its destination context (HTML, URLs, etc.)
 * - Never rely solely on client-side validation
 */

/**
 * Clean a string for safe HTML display.
 * Encodes dangerous characters to prevent XSS attacks.
 *
 * @param string|null $rawContent User-provided content
 * @return string Safe HTML-encoded content
 */
function escapeForHTML(?string $rawContent): string {
    if ($rawContent === null) {
        return '';
    }
    // ENT_QUOTES encodes both single and double quotes
    // UTF-8 properly specified to block multi-byte encoding attacks
    return htmlspecialchars($rawContent, ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

/**
 * Validate account identifier (username).
 * Constraints: 3-50 alphanumeric characters plus underscores only.
 *
 * @param string $accountId Proposed username/account identifier
 * @return array ['isValid' => bool, 'errorMsg' => string|null]
 */
function validateAccountId(string $accountId): array {
    $accountId = trim($accountId);

    if (empty($accountId)) {
        return ['isValid' => false, 'errorMsg' => 'Account identifier is required.'];
    }

    if (strlen($accountId) < 3 || strlen($accountId) > 50) {
        return ['isValid' => false, 'errorMsg' => 'Account identifier must be 3-50 characters.'];
    }

    // Strict allowlist: only alphanumeric and underscores
    // \A and \z anchors prevent multiline bypass attempts
    if (!preg_match('/\A[a-zA-Z0-9_]{3,50}\z/', $accountId)) {
        return ['isValid' => false, 'errorMsg' => 'Use only letters, numbers, and underscores.'];
    }

    return ['isValid' => true, 'errorMsg' => null];
}

/**
 * Validate email address format.
 *
 * @param string $emailAddr Email to validate
 * @return array ['isValid' => bool, 'errorMsg' => string|null]
 */
function validateEmailAddress(string $emailAddr): array {
    $emailAddr = trim($emailAddr);

    if (empty($emailAddr)) {
        return ['isValid' => false, 'errorMsg' => 'Email address is required.'];
    }

    if (strlen($emailAddr) > 255) {
        return ['isValid' => false, 'errorMsg' => 'Email address is too long (max 255 chars).'];
    }

    // Use PHP's built-in filter for robust email validation
    // Safer than custom regex patterns which can be vulnerable to ReDoS
    if (!filter_var($emailAddr, FILTER_VALIDATE_EMAIL)) {
        return ['isValid' => false, 'errorMsg' => 'Please provide a valid email address.'];
    }

    return ['isValid' => true, 'errorMsg' => null];
}

/**
 * Validate password strength.
 * Requirements: minimum 8 characters, must include uppercase, lowercase, digit, and special character.
 *
 * @param string $secretKey Password to validate
 * @return array ['isValid' => bool, 'errorMsg' => string|null]
 */
function validateSecretKey(string $secretKey): array {
    if (empty($secretKey)) {
        return ['isValid' => false, 'errorMsg' => 'Password is required.'];
    }

    if (strlen($secretKey) < 8) {
        return ['isValid' => false, 'errorMsg' => 'Password must be at least 8 characters.'];
    }

    if (strlen($secretKey) > 72) {
        // Bcrypt has a 72-byte limit; enforcing here prevents silent truncation
        return ['isValid' => false, 'errorMsg' => 'Password must not exceed 72 characters.'];
    }

    if (!preg_match('/[a-z]/', $secretKey)) {
        return ['isValid' => false, 'errorMsg' => 'Password must contain lowercase letters.'];
    }

    if (!preg_match('/[A-Z]/', $secretKey)) {
        return ['isValid' => false, 'errorMsg' => 'Password must contain uppercase letters.'];
    }

    if (!preg_match('/[0-9]/', $secretKey)) {
        return ['isValid' => false, 'errorMsg' => 'Password must contain digits.'];
    }

    if (!preg_match('/[!@#$%^&*()_+\-=\[\]{};:\'",.<>?\\/\\\\|`~]/', $secretKey)) {
        return ['isValid' => false, 'errorMsg' => 'Password must contain special characters.'];
    }

    return ['isValid' => true, 'errorMsg' => null];
}

/**
 * Validate a monetary amount.
 *
 * @param mixed $amount The amount to validate
 * @return array ['isValid' => bool, 'errorMsg' => string|null]
 */
function validateMonetaryAmount($amount): array {
    if (empty($amount) && $amount !== 0 && $amount !== '0') {
        return ['isValid' => false, 'errorMsg' => 'Amount is required.'];
    }

    // Strict allowlist: plain decimal only — digits with an optional dot and 1-2 decimal places.
    // FILTER_VALIDATE_FLOAT silently accepts scientific notation (1e1, 1E+10),
    // so we reject it here before the float check.
    if (!preg_match('/^\d+(\.\d{1,2})?$/', (string) $amount)) {
        return ['isValid' => false, 'errorMsg' => 'Amount must be a plain number (e.g. 10.50).'];
    }

    $numericAmount = filter_var($amount, FILTER_VALIDATE_FLOAT);
    if ($numericAmount === false) {
        return ['isValid' => false, 'errorMsg' => 'Amount must be a valid number.'];
    }

    if ($numericAmount <= 0) {
        return ['isValid' => false, 'errorMsg' => 'Amount must be greater than zero.'];
    }

    if ($numericAmount > 1000000) {
        return ['isValid' => false, 'errorMsg' => 'Amount exceeds maximum transaction limit.'];
    }

    return ['isValid' => true, 'errorMsg' => null];
}

/**
 * Validate comment/memo text.
 *
 * @param string $memo Optional comment text
 * @return array ['isValid' => bool, 'errorMsg' => string|null]
 */
function validateTransferMemo(string $memo = ''): array {
    if (strlen($memo) > 500) {
        return ['isValid' => false, 'errorMsg' => 'Memo must be 500 characters or less.'];
    }

    return ['isValid' => true, 'errorMsg' => null];
}

/**
 * Validate file upload (profile avatar).
 *
 * @param array $fileData $_FILES array element
 * @return array ['isValid' => bool, 'errorMsg' => string|null]
 */
function validateAvatarUpload(array $fileData): array {
    if (!isset($fileData['tmp_name']) || empty($fileData['tmp_name'])) {
        return ['isValid' => false, 'errorMsg' => 'No file selected.'];
    }

    // Check file size: max 2MB
    $maxFileSize = 2 * 1024 * 1024;
    if ($fileData['size'] > $maxFileSize) {
        return ['isValid' => false, 'errorMsg' => 'File size must not exceed 2MB.'];
    }

    // Validate MIME type
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mimeType = finfo_file($finfo, $fileData['tmp_name']);
    finfo_close($finfo);

    $allowedMimes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    if (!in_array($mimeType, $allowedMimes, true)) {
        return ['isValid' => false, 'errorMsg' => 'Only JPG, PNG, GIF, and WebP images allowed.'];
    }

    // SECURITY FIX: Validate that the file is actually a parseable image
    // getimagesize() reads image headers — rejects polyglot files with valid
    // MIME magic bytes but invalid/missing image structure
    $imageInfo = @getimagesize($fileData['tmp_name']);
    if ($imageInfo === false || $imageInfo[0] <= 0 || $imageInfo[1] <= 0) {
        return ['isValid' => false, 'errorMsg' => 'File is not a valid image.'];
    }

    return ['isValid' => true, 'errorMsg' => null];
}

/**
 * Sanitize user bio/profile text.
 *
 * @param string $bioText User-provided biography
 * @return string Sanitized biography (plain text, no HTML)
 */
function sanitizeBioText(string $bioText): string {
    // Trim whitespace
    $bioText = trim($bioText);

    // Remove null bytes
    $bioText = str_replace("\0", '', $bioText);

    // Limit to 500 characters
    if (mb_strlen($bioText, 'UTF-8') > 500) {
        $bioText = mb_substr($bioText, 0, 500, 'UTF-8');
    }

    return $bioText;
}
?>
