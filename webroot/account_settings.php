<?php
/**
 * Account Settings Page
 * Allows members to update their profile bio and avatar
 */

define('APP_BASE', dirname(__DIR__));

require_once APP_BASE . '/utilities/security.php';
require_once APP_BASE . '/utilities/session.php';
require_once APP_BASE . '/utilities/operations.php';
require_once APP_BASE . '/utilities/validation.php';
require_once APP_BASE . '/utilities/activity_log.php';

applySecurityHeaders();

$session = validateActiveSession();
if (!$session) {
    header('Location: /signin.php');
    exit;
}

chroniclePageAccess('account_settings.php', $session);

// Rate limit POST requests: block if more than 60 accesses in the last 15 minutes.
// The counter includes GET visits (each page load adds one entry), so the threshold
// is set high enough that a normal user navigating back and forth won't be blocked,
// while still stopping automated flood attacks.
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $dbConn = getPDOConnection();
    $rateLimitStmt = $dbConn->prepare(
        'SELECT COUNT(*) FROM event_chronicle
         WHERE member_id = :member_id
           AND page_path = :page
           AND access_timestamp > DATE_SUB(NOW(), INTERVAL 15 MINUTE)'
    );
    $rateLimitStmt->execute([':member_id' => $session['member_id'], ':page' => 'account_settings.php']);
    if ((int) $rateLimitStmt->fetchColumn() >= 60) {
        http_response_code(429);
        exit('Too many requests. Please wait before making further changes.');
    }
}

$successMsg = '';
$errorMsg   = '';

// Fetch member profile
$memberProfile = fetchMemberProfile($session['member_id']);
if (!$memberProfile) {
    destroyActiveSession();
    header('Location: /signin.php');
    exit;
}

// Handle profile update
if (isset($_POST['update_profile'])) {
    $csrfToken = $_POST['csrf_token'] ?? '';
    if (!validateCSRFToken($csrfToken)) {
        $errorMsg = 'Security validation failed.';
    } else {
        $bioText = trim($_POST['bio'] ?? '');

        $updateData = [];
        if (!empty($bioText)) {
            $updateData['bio'] = $bioText;
        }

        if (!empty($updateData)) {
            $updateResult = modifyMemberProfile($session['member_id'], $updateData);
            if ($updateResult['success']) {
                $successMsg = 'Profile updated successfully!';
                // Refresh profile
                $memberProfile = fetchMemberProfile($session['member_id']);
            } else {
                $errorMsg = $updateResult['errorMsg'];
            }
        }
    }
}

// Handle avatar upload
if (isset($_POST['upload_avatar'])) {
    $csrfToken = $_POST['csrf_token'] ?? '';
    if (!validateCSRFToken($csrfToken)) {
        $errorMsg = 'Security validation failed.';
    } else if (empty($_FILES)) {
        $errorMsg = 'No file uploaded.';
    } else {
        $uploadResult = updateProfilePhoto($session['member_id'], $_FILES['avatar']);
        if ($uploadResult['success']) {
            $successMsg = 'Profile photo updated!';
            $memberProfile = fetchMemberProfile($session['member_id']);
        } else {
            $errorMsg = $uploadResult['errorMsg'];
        }
    }
}

$csrfToken = produceCSRFToken();
$pageTitle = 'Account Settings';
require_once APP_BASE . '/layouts/header.php';
?>

<div class="settings-container">
    <?php if ($successMsg): ?>
        <div class="alert alert-success"><?php echo escapeForHTML($successMsg); ?></div>
    <?php endif; ?>

    <?php if ($errorMsg): ?>
        <div class="alert alert-error"><?php echo escapeForHTML($errorMsg); ?></div>
    <?php endif; ?>

    <!-- Profile Settings -->
    <div class="settings-card">
        <h2 class="card-title">Profile Information</h2>
        
        <form method="POST" action="/account_settings.php" enctype="multipart/form-data">
            <input type="hidden" name="csrf_token" value="<?php echo escapeForHTML($csrfToken); ?>">
            <input type="hidden" name="update_profile" value="1">

            <div class="form-group">
                <label for="bio" class="form-label">Bio / About</label>
                <textarea id="bio" name="bio" class="form-textarea" maxlength="500" rows="3"
                          placeholder="Tell others about yourself..."><?php echo escapeForHTML($memberProfile['member_bio'] ?? ''); ?></textarea>
                <small class="form-hint">500 characters max</small>
            </div>

            <button type="submit" class="btn btn-primary">Save Profile</button>
        </form>
    </div>

    <!-- Avatar Upload -->
    <div class="settings-card">
        <h2 class="card-title">Profile Photo</h2>
        
        <?php if ($memberProfile['profile_photo']): ?>
            <div class="current-avatar">
                <img src="<?php echo escapeForHTML($memberProfile['profile_photo']); ?>" alt="Profile">
            </div>
        <?php endif; ?>

        <form method="POST" action="/account_settings.php" enctype="multipart/form-data">
            <input type="hidden" name="csrf_token" value="<?php echo escapeForHTML($csrfToken); ?>">
            <input type="hidden" name="upload_avatar" value="1">

            <div class="form-group">
                <label for="avatar" class="form-label">Upload Photo</label>
                <input type="file" id="avatar" name="avatar" class="form-input"
                       accept="image/jpeg,image/png,image/gif,image/webp" required>
                <small class="form-hint">JPG, PNG, GIF, or WebP (max 2MB)</small>
            </div>

            <button type="submit" class="btn btn-primary">Upload Photo</button>
        </form>
    </div>

</div>

<?php require_once APP_BASE . '/layouts/footer.php'; ?>
