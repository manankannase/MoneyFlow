<?php
/**
 * Search/Browse Members
 * Allows members to find other accounts
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

chroniclePageAccess('search.php', $session);

$searchTerm = trim($_GET['q'] ?? '');
$searchResults = [];
$rateLimitError = '';

if (strlen($searchTerm) >= 1) {
    $clientIp = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    $dbConn = getPDOConnection();

    $rateLimitStmt = $dbConn->prepare(
        'INSERT INTO search_rate_limit (ip_address)
         SELECT :ip FROM DUAL
         WHERE (
             SELECT COUNT(*) FROM search_rate_limit
             WHERE ip_address = :ip2
               AND searched_at > DATE_SUB(NOW(), INTERVAL 1 MINUTE)
         ) < 10'
    );
    $rateLimitStmt->execute([':ip' => $clientIp, ':ip2' => $clientIp]);

    if ($rateLimitStmt->rowCount() === 0) {
        $rateLimitError = 'Too many searches. Please wait a moment before trying again.';
    } else {
        $searchResults = discoverMembers($searchTerm, 5);
    }
}

$pageTitle = 'Find Members';
require_once APP_BASE . '/layouts/header.php';
?>

<div class="search-container">
    <div class="search-card">
        <h2 class="card-title">Find Members</h2>

        <form method="GET" action="/search.php" class="search-form">
            <div class="input-group">
                <input type="text" name="q" class="form-input" 
                       placeholder="Search by account name or ID..."
                       value="<?php echo escapeForHTML($searchTerm); ?>" autofocus>
                <button type="submit" class="btn btn-primary">Search</button>
            </div>
        </form>

        <?php if ($rateLimitError): ?>
            <div class="alert alert-error"><?php echo escapeForHTML($rateLimitError); ?></div>
        <?php endif; ?>

        <?php if ($searchTerm && !empty($searchResults)): ?>
            <div class="results-section">
                <h3>Search Results</h3>
                <table class="members-table">
                    <thead>
                        <tr>
                            <th>Account ID (Numeric)</th>
                            <th>Account Name</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($searchResults as $member): ?>
                            <tr>
                                <td><?php echo escapeForHTML($member['id']); ?></td>
                                <td><?php echo escapeForHTML($member['account_name']); ?></td>
                                <td>
                                    <a href="/transfer.php?to=<?php echo (int)$member['id']; ?>" 
                                       class="btn btn-small btn-primary">Send Money</a>
                                    <a href="/member_profile.php?id=<?php echo (int)$member['id']; ?>" 
                                       class="btn btn-small btn-outline">View Profile</a>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php elseif ($searchTerm): ?>
            <p class="text-muted">No members found.</p>
        <?php else: ?>
            <p class="text-muted">Enter a search term to find members.</p>
        <?php endif; ?>
    </div>
</div>

<?php require_once APP_BASE . '/layouts/footer.php'; ?>
