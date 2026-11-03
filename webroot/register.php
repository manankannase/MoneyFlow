<?php
/**
 * Registration Page
 */
require_once __DIR__ . '/../utilities/security.php';
require_once __DIR__ . '/../utilities/session.php';
require_once __DIR__ . '/../utilities/auth.php';
require_once __DIR__ . '/../utilities/validation.php';

sendSecurityHeaders();

// Redirect if already logged in
$session = validateSession();
if ($session) {
    header('Location: /dashboard.php');
    exit;
}

$error     = '';
$success   = '';
$pageTitle = 'Register';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    checkPreauthCsrf();
    $accountId  = trim($_POST['account_id'] ?? '');
    $email      = trim($_POST['email'] ?? '');
    $password   = $_POST['password'] ?? '';
    $confirmPwd = $_POST['confirm_password'] ?? '';

    if (!consumeRateLimit('register-ip', getClientIp(), 10, 3600)) {
        http_response_code(429); $error = 'Too many registration attempts.';
    } elseif (!validateAccountName($accountId)) {
        $error = 'Username must be 3-30 characters: letters, digits, underscores only.';
    } elseif (!validateEmail($email)) {
        $error = 'Please enter a valid email address.';
    } elseif (!validatePassword($password)) {
        $error = 'Password must be 12–72 bytes and include uppercase, lowercase, digit, and special character.';
    } elseif (!hash_equals($password, $confirmPwd)) {
        $error = 'Passwords do not match.';
    } else {
        $result = createMemberAccount($accountId, $email, $password);
        if ($result['success']) {
            $success = 'Account created successfully! You can now sign in.';
        } else {
            $error = $result['errorMsg'];
        }
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'GET') preauthCsrf(true);
require_once __DIR__ . '/../layouts/header.php';
?>
<div class="auth-container">
    <h1>Create Account</h1>
    <?php if ($error): ?>
        <div class="alert alert-error"><?= h($error) ?></div>
    <?php endif; ?>
    <?php if ($success): ?>
        <div class="alert alert-success"><?= h($success) ?></div>
    <?php endif; ?>
    <form method="post" action="/register.php" class="auth-form" id="registerForm">
        <input type="hidden" name="csrf_token" value="<?= h(preauthCsrf(true)) ?>">
        <div class="form-group">
            <label for="account_id">Username</label>
            <input type="text" id="account_id" name="account_id"
                   required maxlength="30" autocomplete="username"
                   pattern="[a-zA-Z0-9_]{3,30}"
                   value="<?= h($_POST['account_id'] ?? '') ?>">
            <small>3-30 characters: letters, digits, underscores</small>
        </div>
        <div class="form-group">
            <label for="email">Email</label>
            <input type="email" id="email" name="email"
                   required maxlength="255" autocomplete="email"
                   value="<?= h($_POST['email'] ?? '') ?>">
        </div>
        <div class="form-group">
            <label for="password">Password</label>
            <input type="password" id="password" name="password"
                   required maxlength="72" autocomplete="new-password">
            <small>12–72 bytes: uppercase, lowercase, digit, special character</small>
        </div>
        <div class="form-group">
            <label for="confirm_password">Confirm Password</label>
            <input type="password" id="confirm_password" name="confirm_password"
                   required maxlength="72" autocomplete="new-password">
        </div>
        <button type="submit" class="btn btn-primary">Create Account</button>
    </form>
    <p class="auth-link">Already have an account? <a href="/login.php">Sign In</a></p>
</div>
<?php require_once __DIR__ . '/../layouts/footer.php'; ?>
