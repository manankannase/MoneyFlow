<?php
/**
 * Member Sign-Up Page
 * New account registration
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
$regCount  = 0;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // SECURITY FIX N3: Validate CSRF token on registration
    $csrfToken = $_POST['csrf_token'] ?? '';
    if (!validateCSRFToken($csrfToken)) {
        $errorMsg = 'Security validation failed. Please try again.';
    } else {
        $accountId = trim($_POST['account_id'] ?? '');
        $emailAddr = trim($_POST['email_addr'] ?? '');
        $secretKey = $_POST['secret_key'] ?? '';

        $registrationResult = createMemberAccount($accountId, $emailAddr, $secretKey);

        if ($registrationResult['success']) {
            chroniclePageAccess('signup.php (success)', null);
            header('Location: /signin.php?signup_done=1');
            exit;
        } else {
            $errorMsg = $registrationResult['errorMsg'];
            // Detect rate limit hit to disable the submit button
            if (str_contains($errorMsg, 'limit reached')) {
                $regCount = 5;
            }
        }
    }
}

// Log page access
chroniclePageAccess('signup.php', null);

$csrfToken = produceCSRFToken();

$pageTitle = 'Create Account';
require_once APP_BASE . '/layouts/header.php';
?>

<div class="auth-container">
    <div class="auth-card">
        <div class="auth-header">
            <h1>Create MoneyFlow Account</h1>
            <p>Join our secure community</p>
        </div>

        <?php if ($errorMsg): ?>
            <div class="alert alert-error"><?php echo escapeForHTML($errorMsg); ?></div>
        <?php endif; ?>

        <form method="POST" action="/signup.php">
            <input type="hidden" name="csrf_token" value="<?php echo escapeForHTML($csrfToken); ?>">
            <div class="form-group">
                <label for="account_id" class="form-label">Account Name</label>
                <input type="text" id="account_id" name="account_id" class="form-input"
                       required maxlength="50" placeholder="Choose unique account name"
                       pattern="[a-zA-Z0-9_]{3,50}" autofocus>
                <small class="form-hint">3-50 characters, alphanumeric and underscores only</small>
            </div>

            <div class="form-group">
                <label for="email_addr" class="form-label">Email Address</label>
                <input type="email" id="email_addr" name="email_addr" class="form-input"
                       required maxlength="255" placeholder="you@example.com">
            </div>

            <div class="form-group">
                <label for="secret_key" class="form-label">Password</label>
                <div class="password-container">
                    <input type="password" id="secret_key" name="secret_key" class="form-input"
                           required maxlength="72" placeholder="Create a strong password">
                    <button type="button" class="password-toggle">Show</button>
                </div>
                <small class="form-hint">Min 8 chars: uppercase, lowercase, digit, special char</small>
            </div>

            <button type="submit" class="btn btn-primary btn-full"
                    <?php if ($regCount >= 5): ?>disabled title="Account creation limit reached"<?php endif; ?>>
                Create Account
            </button>
        </form>

        <div class="auth-footer">
            <p>Already have an account? <a href="/signin.php" class="link">Sign in here</a></p>
        </div>
    </div>
</div>

<?php require_once APP_BASE . '/layouts/footer.php'; ?>
