<?php
/**
 * Member Profile Viewing Page
 * Displays public profile information of other members
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

chroniclePageAccess('member_profile.php', $session);

// Rate limit: max 30 profile views per minute per user to prevent ID enumeration
$dbConn = getPDOConnection();
$profileRateStmt = $dbConn->prepare(
    'SELECT COUNT(*) FROM event_chronicle
     WHERE member_id = :mid
       AND page_path = :page
       AND access_timestamp > DATE_SUB(NOW(), INTERVAL 1 MINUTE)'
);
$profileRateStmt->execute([':mid' => $session['member_id'], ':page' => 'member_profile.php']);
if ((int) $profileRateStmt->fetchColumn() >= 30) {
    http_response_code(429);
    exit('Too many requests. Please slow down.');
}

$profileId = is_string($_GET['id'] ?? null) ? intval($_GET['id']) : 0;

if ($profileId <= 0) {
    header('Location: /search.php');
    exit;
}

$viewedMember = fetchMemberProfile($profileId);
if (!$viewedMember) {
    header('Location: /search.php');
    exit;
}

$pageTitle = 'Member Profile - ' . $viewedMember['account_name'];
require_once APP_BASE . '/layouts/header.php';
?>

<div class="profile-container">
    <div class="profile-card">
        <div class="profile-header">
            <?php if ($viewedMember['profile_photo']): ?>
                <img src="<?php echo escapeForHTML($viewedMember['profile_photo']); ?>" 
                     alt="<?php echo escapeForHTML($viewedMember['account_name']); ?>" class="profile-avatar">
            <?php else: ?>
                <div class="profile-avatar-placeholder">
                    <?php echo strtoupper(substr($viewedMember['account_name'], 0, 1)); ?>
                </div>
            <?php endif; ?>
            
            <h1 class="profile-name"><?php echo escapeForHTML($viewedMember['account_name']); ?></h1>
            <?php if ($profileId === $session['member_id']): ?>
                <p class="profile-email"><?php echo escapeForHTML($viewedMember['email_address']); ?></p>
            <?php endif; ?>
        </div>

        <div class="profile-content">
            <?php if ($viewedMember['member_bio']): ?>
                <section class="profile-section">
                    <h3>About</h3>
                    <p><?php echo escapeForHTML($viewedMember['member_bio']); ?></p>
                </section>
            <?php endif; ?>

            <section class="profile-section">
                <h3>Member Since</h3>
                <p><?php echo escapeForHTML(date('F j, Y', strtotime($viewedMember['created_at']))); ?></p>
            </section>

            <div class="profile-actions">
                <a href="/transfer.php?to=<?php echo (int)$viewedMember['id']; ?>" 
                   class="btn btn-primary">Send Money</a>
            </div>
        </div>
    </div>
</div>

<?php require_once APP_BASE . '/layouts/footer.php'; ?>
