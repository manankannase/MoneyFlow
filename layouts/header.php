<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= h($pageTitle ?? 'MoneyFlow') ?> — MoneyFlow</title>
    <link rel="stylesheet" href="/css/main.css">
</head>
<body>
    <header class="site-header">
        <div class="header-inner">
            <a href="/dashboard.php" class="logo">💸 MoneyFlow</a>
            <?php if (!empty($session)): ?>
            <nav class="main-nav">
                <a href="/dashboard.php">Dashboard</a>
                <a href="/transfer.php">Transfer</a>
                <a href="/history.php">History</a>
                <a href="/search.php">Search</a>
                <a href="/profile.php">Profile</a>
                <form method="post" action="/logout.php"><input type="hidden" name="csrf_token" value="<?= h($session['csrf_token']) ?>"><button class="btn-logout" type="submit">Logout</button></form>
            </nav>
            <?php endif; ?>
        </div>
    </header>
    <main class="main-content">
    <p class="balance-info">Portfolio application · simulated INR balances</p>
