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

// FIX #21: Server-side math CAPTCHA — no external CDN/API needed.
// Generates a random addition question; answer stored in PHP session only
// (never sent to client), so an attacker cannot compute it from page source.
// Note: validateActiveSession() above always calls session_start(), so $_SESSION
// is already available here — no explicit session_start() needed.
if (empty($_SESSION['captcha_answer']) || empty($_SESSION['captcha_question'])) {
    $a = random_int(1, 15);
    $b = random_int(1, 15);
    $_SESSION['captcha_answer']   = $a + $b;
    $_SESSION['captcha_question'] = "What is {$a} + {$b}?";
}

$errorMsg = '';
$regCount  = 0;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // SECURITY FIX N3: Validate CSRF token on registration
    $csrfToken = $_POST['csrf_token'] ?? '';
    if (!validateCSRFToken($csrfToken)) {
        $errorMsg = 'Security validation failed. Please try again.';
    } else {
        // FIX #21: Validate CAPTCHA before doing anything else.
        // Use == (not ===) because form input is a string; intval converts safely.
        $captchaInput = is_string($_POST['captcha_answer'] ?? null) ? intval($_POST['captcha_answer']) : -1;
        if ($captchaInput !== (int) $_SESSION['captcha_answer']) {
            $errorMsg = 'Incorrect CAPTCHA answer. Please try again.';
            // Regenerate so the same question cannot be replayed
            $a = random_int(1, 15);
            $b = random_int(1, 15);
            $_SESSION['captcha_answer']   = $a + $b;
            $_SESSION['captcha_question'] = "What is {$a} + {$b}?";
        } else {
            // Consumed — regenerate immediately so the same answer cannot be replayed
            $a = random_int(1, 15);
            $b = random_int(1, 15);
            $_SESSION['captcha_answer']   = $a + $b;
            $_SESSION['captcha_question'] = "What is {$a} + {$b}?";

            $accountId = is_string($_POST['account_id'] ?? null) ? trim($_POST['account_id']) : '';
            $emailAddr = is_string($_POST['email_addr'] ?? null) ? trim($_POST['email_addr']) : '';
            $secretKey = is_string($_POST['secret_key'] ?? null) ? $_POST['secret_key'] : '';

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
}

// Log page access
chroniclePageAccess('signup.php', null);

$csrfToken       = produceCSRFToken();
$captchaQuestion = $_SESSION['captcha_question'];

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

            <!-- FIX #21: Math CAPTCHA — prevents automated account creation via VPN rotation -->
            <div class="form-group">
                <label for="captcha_answer" class="form-label">
                    Security Check: <?php echo escapeForHTML($captchaQuestion); ?>
                </label>
                <input type="number" id="captcha_answer" name="captcha_answer"
                       class="form-input" required min="0" max="30"
                       placeholder="Enter your answer" autocomplete="off">
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
