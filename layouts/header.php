<?php
/**
 * Page Header Template
 * Included at the beginning of every page
 */
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title><?php echo isset($pageTitle) ? escapeForHTML($pageTitle) . ' | MoneyFlow' : 'MoneyFlow'; ?></title>
    <link rel="stylesheet" href="/css/main.css">
</head>
<body>
    <div class="app-wrapper">
        <?php if ($session = validateActiveSession()): ?>
        <header class="navbar">
            <div class="navbar-content">
                <h2 class="navbar-brand">
                    <a href="/dashboard.php" class="brand-link">MoneyFlow</a>
                </h2>
                <nav class="nav-menu">
                    <ul class="nav-items">
                        <li><a href="/dashboard.php" class="nav-link">Dashboard</a></li>
                        <li><a href="/transfer.php" class="nav-link">Send Money</a></li>
                        <li><a href="/search.php" class="nav-link">Find Members</a></li>
                        <li><a href="/transaction_history.php" class="nav-link">History</a></li>
                        <li><a href="/account_settings.php" class="nav-link">Settings</a></li>
                        <li>
                            <form method="POST" action="/logout.php" style="display:inline;">
                                <input type="hidden" name="csrf_token" value="<?php echo escapeForHTML($session['csrf_token']); ?>">
                                <button type="submit" class="nav-link danger logout-btn">Logout</button>
                            </form>
                        </li>
                    </ul>
                </nav>
                <div class="navbar-user">
                    <span class="user-info">Welcome, <strong><?php echo escapeForHTML($session['account_name']); ?></strong></span>
                </div>
            </div>
        </header>
        <?php endif; ?>
        <main class="content-area">
