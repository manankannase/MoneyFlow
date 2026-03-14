<?php
/**
 * Member Sign-In Page
 * Handles user authentication with rate limiting and security measures
 */

define('APP_BASE', dirname(__DIR__));

require_once APP_BASE . '/utilities/security.php';
require_once APP_BASE . '/utilities/session.php';
require_once APP_BASE . '/utilities/auth.php';
require_once APP_BASE . '/utilities/validation.php';
require_once APP_BASE . '/utilities/activity_log.php';

applySecurityHeaders();

// Redirect if already authenticated
$session = validateActiveSession();
if ($session) {
    header('Location: /dashboard.php');
    exit;
}

$errorMsg = '';
$successMsg = '';

// Check for successful signup redirect
if (isset($_GET['signup_done']) && $_GET['signup_done'] === '1') {
    $successMsg = 'Account created! Please sign in with your credentials.';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // SECURITY FIX: Validate CSRF token on login
    $csrfToken = $_POST['csrf_token'] ?? '';
    if (!validateCSRFToken($csrfToken)) {
        $errorMsg = 'Security validation failed. Please try again.';
    } else {
        $accountId = trim($_POST['account_id'] ?? '');
        $secretKey = $_POST['secret_key'] ?? '';

        if (empty($accountId) || empty($secretKey)) {
            $errorMsg = 'Please provide both account name and password.';
        } else {
            $authResult = authenticateCredentials($accountId, $secretKey);

            if ($authResult['success']) {
                chroniclePageAccess('signin.php (success)', null);
                header('Location: /dashboard.php');
                exit;
            } else {
                $errorMsg = $authResult['errorMsg'];
                chroniclePageAccess('signin.php (failed)', null);
            }
        }
    }
}

// Log page access
chroniclePageAccess('signin.php', null);

$csrfToken = produceCSRFToken();

$pageTitle = 'Sign In';
require_once APP_BASE . '/layouts/header.php';
?>

<div class="auth-container">
    <div class="auth-card">
        <div class="auth-header">
            <h1>Sign In to MoneyFlow</h1>
            <p>Access your account securely</p>
        </div>

        <?php if ($errorMsg): ?>
            <div class="alert alert-error"><?php echo escapeForHTML($errorMsg); ?></div>
        <?php endif; ?>

        <?php if ($successMsg): ?>
            <div class="alert alert-success"><?php echo escapeForHTML($successMsg); ?></div>
        <?php endif; ?>

        <form method="POST" action="/signin.php" autocomplete="off">
            <input type="hidden" name="csrf_token" value="<?php echo escapeForHTML($csrfToken); ?>">
            <div class="form-group">
                <label for="account_id" class="form-label">Account Name</label>
                <input type="text" id="account_id" name="account_id" class="form-input"
                       required maxlength="50" placeholder="Enter your account name" autofocus>
            </div>

            <div class="form-group">
                <label for="secret_key" class="form-label">Password</label>
                <div class="password-container">
                    <input type="password" id="secret_key" name="secret_key" class="form-input"
                           required maxlength="72" placeholder="Enter your password">
                    <button type="button" class="password-toggle">Show</button>
                </div>
            </div>

            <button type="submit" class="btn btn-primary btn-full">Sign In</button>
        </form>

        <div class="auth-footer">
            <p>Don't have an account? <a href="/signup.php" class="link">Create one here</a></p>
        </div>
    </div>
</div>

<?php require_once APP_BASE . '/layouts/footer.php'; ?>
