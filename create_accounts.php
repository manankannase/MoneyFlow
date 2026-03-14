<?php
/**
 * Account Creator Script
 * Creates test/seed member accounts for the War Game deployment.
 *
 * FIX V6: Real team member names and predictable passwords have been removed.
 * Passwords are now read from environment variables. If not set, a random
 * strong password is generated and printed ONCE (so you can note it down).
 *
 * Usage: docker exec moneyflow-webserver php /var/www/html/create_accounts.php
 *
 * Set passwords via environment (in docker-compose.yml):
 *   ACCOUNT_PASS_1=SomeStr0ng!Pass1
 *   ACCOUNT_PASS_2=SomeStr0ng!Pass2
 *   ...etc
 */

define('APP_BASE', __DIR__);
require_once APP_BASE . '/utilities/auth.php';

// Helper: read password from env or generate a random strong one
function resolveAccountPassword(string $envKey): string {
    $pass = getenv($envKey);
    if ($pass && strlen($pass) >= 12) {
        return $pass;
    }
    // Generate a random 20-char password: upper + lower + digit + symbol
    $chars  = 'abcdefghijkmnpqrstuvwxyz';
    $upper  = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
    $digits = '23456789';
    $syms   = '@#$!%^&*';
    $pool   = $chars . $upper . $digits . $syms;
    $pwd    = $upper[random_int(0, strlen($upper)-1)]
            . $digits[random_int(0, strlen($digits)-1)]
            . $syms[random_int(0, strlen($syms)-1)];
    for ($i = 0; $i < 17; $i++) {
        $pwd .= $pool[random_int(0, strlen($pool)-1)];
    }
    return str_shuffle($pwd);
}

// Generic usernames — no real team member names in the submitted zip
$accounts = [
    ['account_id' => 'player1', 'email' => 'player1@moneyflow.local', 'env_key' => 'ACCOUNT_PASS_1'],
    ['account_id' => 'player2', 'email' => 'player2@moneyflow.local', 'env_key' => 'ACCOUNT_PASS_2'],
    ['account_id' => 'player3', 'email' => 'player3@moneyflow.local', 'env_key' => 'ACCOUNT_PASS_3'],
    ['account_id' => 'player4', 'email' => 'player4@moneyflow.local', 'env_key' => 'ACCOUNT_PASS_4'],
    ['account_id' => 'player5', 'email' => 'player5@moneyflow.local', 'env_key' => 'ACCOUNT_PASS_5'],
];

echo "=== MoneyFlow Account Creator ===\n\n";

foreach ($accounts as $acct) {
    $password = resolveAccountPassword($acct['env_key']);
    echo "Creating account: {$acct['account_id']}... ";

    $result = createMemberAccount($acct['account_id'], $acct['email'], $password);

    if ($result['success']) {
        // Print the password here (visible only during deployment, not stored in source)
        echo "OK (ID: {$result['memberId']}) — password: $password\n";
    } else {
        echo "FAILED: {$result['errorMsg']}\n";
    }
}

echo "\nEach account starts with Rs.100.00 balance\n";
echo "\nNOTE: Save the passwords printed above. They are not stored in source code.\n";
?>
