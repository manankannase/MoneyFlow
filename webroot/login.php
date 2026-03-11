<?php
/**
 * Login Page
 */
require_once __DIR__ . '/../utilities/security.php';
require_once __DIR__ . '/../utilities/session.php';
require_once __DIR__ . '/../utilities/auth.php';
require_once __DIR__ . '/../utilities/activity_log.php';
require_once __DIR__ . '/../utilities/validation.php';

sendSecurityHeaders();

// Redirect if already logged in
$session = validateSession();
if ($session) {
    header('Location: /dashboard.php');
    exit;
}

$error   = '';
$pageTitle = 'Login';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isRateLimited(10, 900)) {
        $error = 'Too many login attempts. Please wait 15 minutes before trying again.';
    } else {
        $accountId = trim($_POST['account_id'] ?? '');
        $password  = $_POST['password'] ?? '';

        $loginResult = verifyLogin($accountId, $password);

        if ($loginResult['success']) {
            createSession((int) $loginResult['member']['id']);
            logPageAccess((int) $loginResult['member']['id'], $loginResult['member']['account_name']);
            header('Location: /dashboard.php');
            exit;
        } else {
            recordFailedAuth($accountId);
            $error = 'Invalid credentials.';
        }
    }
}

require_once __DIR__ . '/../layouts/header.php';
?>
<div class="auth-container">
    <h1>Sign In</h1>
    <?php if ($error): ?>
        <div class="alert alert-error"><?= h($error) ?></div>
    <?php endif; ?>
    <form method="post" action="/login.php" class="auth-form">
        <div class="form-group">
            <label for="account_id">Username</label>
            <input type="text" id="account_id" name="account_id"
                   required autocomplete="username"
                   maxlength="30" pattern="[a-zA-Z0-9_]{3,30}">
        </div>
        <div class="form-group">
            <label for="password">Password</label>
            <input type="password" id="password" name="password"
                   required autocomplete="current-password" maxlength="255">
        </div>
        <button type="submit" class="btn btn-primary">Sign In</button>
    </form>
    <p class="auth-link">Don't have an account? <a href="/register.php">Register</a></p>
</div>
<?php require_once __DIR__ . '/../layouts/footer.php'; ?>
