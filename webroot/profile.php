<?php
/**
 * Profile Page — view and update profile info and avatar
 */
require_once __DIR__ . '/../utilities/security.php';
require_once __DIR__ . '/../utilities/session.php';
require_once __DIR__ . '/../utilities/operations.php';
require_once __DIR__ . '/../utilities/activity_log.php';
require_once __DIR__ . '/../utilities/validation.php';

sendSecurityHeaders();

$session = validateSession();
if (!$session) {
    header('Location: /login.php');
    exit;
}

logPageAccess((int) $session['member_id'], $session['account_name']);

$error     = '';
$success   = '';
$pageTitle = 'My Profile';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // CSRF validation
    $csrfToken = $_POST['csrf_token'] ?? '';
    if (!validateCsrfToken($csrfToken, $session['csrf_token'])) {
        $error = 'Invalid request. Please try again.';
    } else {
        $action = $_POST['action'] ?? '';

        if ($action === 'update_profile') {
            $bio   = trim($_POST['bio'] ?? '');
            $email = trim($_POST['email'] ?? '');

            $result = updateProfile((int) $session['member_id'], $bio, $email);
            if ($result['success']) {
                $success = 'Profile updated successfully.';
                $session = validateSession();  // refresh session data
            } else {
                $error = $result['errorMsg'];
            }
        } elseif ($action === 'upload_avatar' && isset($_FILES['avatar'])) {
            $result = saveAvatar((int) $session['member_id'], $_FILES['avatar']);
            if ($result['success']) {
                $success = 'Profile photo updated.';
                $session = validateSession();
            } else {
                $error = $result['errorMsg'];
            }
        }
    }
}

require_once __DIR__ . '/../layouts/header.php';
?>
<div class="profile-container">
    <h1>My Profile</h1>
    <?php if ($error): ?>
        <div class="alert alert-error"><?= h($error) ?></div>
    <?php endif; ?>
    <?php if ($success): ?>
        <div class="alert alert-success"><?= h($success) ?></div>
    <?php endif; ?>

    <div class="profile-header">
        <div class="profile-avatar">
            <?php if (!empty($session['profile_photo']) && strpos($session['profile_photo'], '/') === false && strpos($session['profile_photo'], '\\') === false): ?>
                <img src="/uploads/avatars/<?= h(basename($session['profile_photo'])) ?>"
                     alt="Profile photo">
            <?php else: ?>
                <span class="avatar-placeholder large">
                    <?= h(strtoupper(substr($session['account_name'], 0, 1))) ?>
                </span>
            <?php endif; ?>
        </div>
        <div>
            <h2><?= h($session['account_name']) ?></h2>
            <p><?= h($session['email_address']) ?></p>
            <p class="balance">Balance: <strong>₹<?= h(number_format((float)$session['account_balance'], 2)) ?></strong></p>
        </div>
    </div>

    <!-- Update Profile Form -->
    <section class="profile-section">
        <h3>Update Profile</h3>
        <form method="post" action="/profile.php" class="profile-form">
            <input type="hidden" name="csrf_token" value="<?= h($session['csrf_token']) ?>">
            <input type="hidden" name="action" value="update_profile">
            <div class="form-group">
                <label for="email">Email</label>
                <input type="email" id="email" name="email" maxlength="255"
                       value="<?= h($session['email_address']) ?>" required autocomplete="email">
            </div>
            <div class="form-group">
                <label for="bio">Bio</label>
                <textarea id="bio" name="bio" maxlength="500" rows="4"><?= h($session['member_bio'] ?? '') ?></textarea>
            </div>
            <button type="submit" class="btn btn-primary">Save Changes</button>
        </form>
    </section>

    <!-- Upload Avatar Form -->
    <section class="profile-section">
        <h3>Profile Photo</h3>
        <form method="post" action="/profile.php" class="profile-form"
              enctype="multipart/form-data">
            <input type="hidden" name="csrf_token" value="<?= h($session['csrf_token']) ?>">
            <input type="hidden" name="action" value="upload_avatar">
            <div class="form-group">
                <label for="avatar">Upload Photo (JPEG, PNG, GIF, WebP — max 2 MB)</label>
                <input type="file" id="avatar" name="avatar"
                       accept="image/jpeg,image/png,image/gif,image/webp">
            </div>
            <button type="submit" class="btn btn-secondary">Upload Photo</button>
        </form>
    </section>
</div>
<?php require_once __DIR__ . '/../layouts/footer.php'; ?>
