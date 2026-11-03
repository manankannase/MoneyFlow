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
 * Requirements: 12-72 bytes, at least one uppercase, lowercase, digit, special char.
 */
function validatePassword(string $password): bool {
    if (strlen($password) < 12 || strlen($password) > 72 || str_contains($password, "\0")) {
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
function amountToMinor(mixed $amount): ?int {
    if (!is_string($amount) || !preg_match('/^(0|[1-9][0-9]{0,9})(?:\.([0-9]{1,2}))?$/D', $amount, $m)) return null;
    return ((int)$m[1]) * 100 + (int)str_pad($m[2] ?? '', 2, '0');
}

function minorToAmount(int $minor): string {
    return intdiv($minor, 100) . '.' . str_pad((string)($minor % 100), 2, '0', STR_PAD_LEFT);
}

function validateAmount(mixed $amount): bool {
    $value = amountToMinor($amount);
    return $value !== null && $value > 0 && $value <= 99999999;
}

/**
 * Validate memo/note text.
 * Max 500 characters, strip control characters.
 */
function validateMemo(string $memo): bool {
    return strlen($memo) <= 500 && !preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', $memo) && preg_match('//u', $memo);
}

/**
 * Sanitize plain text for safe display (HTML-encode).
 * Always use this before outputting any user data to HTML.
 */
function h(string $value): string {
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
