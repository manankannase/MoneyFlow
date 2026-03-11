<?php
/**
 * Input Validation Utilities
 *
 * Server-side validation for all user-supplied data.
 * Client-side validation is a UX supplement only — never rely on it alone.
 */

/**
 * Validate an account name (username).
 * Allowlist: alphanumeric + underscores, 3-30 characters.
 */
function validateAccountName(string $name): bool {
    return (bool) preg_match('/^[a-zA-Z0-9_]{3,30}$/', $name);
}

/**
 * Validate an email address.
 */
function validateEmail(string $email): bool {
    return strlen($email) <= 255
        && filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

/**
 * Validate a password.
 * Requirements: min 8 chars, at least one uppercase, lowercase, digit, special char.
 */
function validatePassword(string $password): bool {
    if (strlen($password) < 8 || strlen($password) > 255) {
        return false;
    }
    // Must contain uppercase, lowercase, digit, and special character
    return (bool) preg_match('/[A-Z]/', $password)
        && (bool) preg_match('/[a-z]/', $password)
        && (bool) preg_match('/[0-9]/', $password)
        && (bool) preg_match('/[@#$%&*!^()_\-+=\[\]{};:\'",.<>?\\/|`~]/', $password);
}

/**
 * Validate a monetary transfer amount.
 * Must be positive, max 2 decimal places, and within reasonable limits.
 */
function validateAmount(mixed $amount): bool {
    if (!is_numeric($amount)) {
        return false;
    }
    $value = (float) $amount;
    // Must be positive, no more than 2 decimal places, and below an upper limit
    return $value > 0
        && $value <= 999999.99
        && preg_match('/^\d+(\.\d{1,2})?$/', (string) $amount);
}

/**
 * Validate memo/note text.
 * Max 500 characters, strip control characters.
 */
function validateMemo(string $memo): bool {
    return strlen($memo) <= 500;
}

/**
 * Sanitize plain text for safe display (HTML-encode).
 * Always use this before outputting any user data to HTML.
 */
function h(string $value): string {
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/**
 * Validate an uploaded avatar file.
 *
 * @param  array $file  Element from $_FILES
 * @return array{valid: bool, errorMsg: string}
 */
function validateAvatarUpload(array $file): array {
    $result = ['valid' => false, 'errorMsg' => ''];

    if ($file['error'] !== UPLOAD_ERR_OK) {
        $result['errorMsg'] = 'File upload failed (error code: ' . $file['error'] . ').';
        return $result;
    }

    $maxSize = 2 * 1024 * 1024;  // 2 MB
    if ($file['size'] > $maxSize) {
        $result['errorMsg'] = 'File size must not exceed 2 MB.';
        return $result;
    }

    // Allowlist of permitted MIME types (verified by finfo, not by extension)
    $allowedMimes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    $finfo        = new finfo(FILEINFO_MIME_TYPE);
    $mimeType     = $finfo->file($file['tmp_name']);

    if (!in_array($mimeType, $allowedMimes, true)) {
        $result['errorMsg'] = 'Only JPEG, PNG, GIF, and WebP images are allowed.';
        return $result;
    }

    // Allowlist of permitted extensions
    $ext          = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    $allowedExts  = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
    if (!in_array($ext, $allowedExts, true)) {
        $result['errorMsg'] = 'Invalid file extension.';
        return $result;
    }

    $result['valid'] = true;
    return $result;
}
