<?php
/**
 * Member Search Page
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

$query     = trim($_GET['q'] ?? '');
$results   = [];
$pageTitle = 'Search Members';

if (!empty($query)) {
    $results = searchMembers($query, (int) $session['member_id']);
}

require_once __DIR__ . '/../layouts/header.php';
?>
<div class="search-container">
    <h1>Find Members</h1>
    <form method="get" action="/search.php" class="search-form">
        <div class="form-group search-input-group">
            <input type="text" name="q" placeholder="Search by username..."
                   value="<?= h($query) ?>" maxlength="30" autocomplete="off">
            <button type="submit" class="btn btn-primary">Search</button>
        </div>
    </form>

    <?php if (!empty($query) && empty($results)): ?>
        <p class="empty-state">No members found for "<?= h($query) ?>".</p>
    <?php endif; ?>

    <?php if (!empty($results)): ?>
        <div class="member-grid">
        <?php foreach ($results as $member): ?>
            <div class="member-card">
                <div class="member-avatar">
                    <?php if (!empty($member['profile_photo'])): ?>
                        <img src="/uploads/avatars/<?= h($member['profile_photo']) ?>"
                             alt="<?= h($member['account_name']) ?>'s avatar">
                    <?php else: ?>
                        <span class="avatar-placeholder"><?= h(strtoupper(substr($member['account_name'], 0, 1))) ?></span>
                    <?php endif; ?>
                </div>
                <div class="member-info">
                    <strong><?= h($member['account_name']) ?></strong>
                    <?php if (!empty($member['member_bio'])): ?>
                        <p><?= h(substr($member['member_bio'], 0, 100)) ?></p>
                    <?php endif; ?>
                </div>
                <a href="/transfer.php?recipient=<?= urlencode($member['account_name']) ?>"
                   class="btn btn-sm btn-primary">Send Money</a>
            </div>
        <?php endforeach; ?>
        </div>
    <?php endif; ?>
</div>
<?php require_once __DIR__ . '/../layouts/footer.php'; ?>
