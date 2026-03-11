<?php
/**
 * Test Account Creator Script
 * Creates sample member accounts for testing
 *
 * WARNING: This script is for DEVELOPMENT/TESTING only.
 * Do NOT run in production environments.
 *
 * Usage: docker exec moneyflow-webserver php /var/www/html/create_accounts.php
 */

// Block execution in production
$appEnv = getenv('APP_ENV') ?: 'production';
if ($appEnv === 'production') {
    echo "ERROR: This script cannot run in production environment.\n";
    echo "Set APP_ENV=development in your .env file to use this script.\n";
    exit(1);
}

define('APP_BASE', __DIR__);

require_once APP_BASE . '/utilities/auth.php';

/**
 * Generate a cryptographically secure random password
 */
function generateSecurePassword(int $length = 16): string {
    $uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $lowercase = 'abcdefghijklmnopqrstuvwxyz';
    $digits    = '0123456789';
    $special   = '@#$%&*!';

    // Ensure at least one of each required character type
    $password = $uppercase[random_int(0, strlen($uppercase) - 1)]
              . $lowercase[random_int(0, strlen($lowercase) - 1)]
              . $digits[random_int(0, strlen($digits) - 1)]
              . $special[random_int(0, strlen($special) - 1)];

    $allChars = $uppercase . $lowercase . $digits . $special;
    for ($i = 4; $i < $length; $i++) {
        $password .= $allChars[random_int(0, strlen($allChars) - 1)];
    }

    // Fisher-Yates shuffle for uniform distribution
    $passwordArray = str_split($password);
    for ($i = count($passwordArray) - 1; $i > 0; $i--) {
        $j = random_int(0, $i);
        [$passwordArray[$i], $passwordArray[$j]] = [$passwordArray[$j], $passwordArray[$i]];
    }

    return implode('', $passwordArray);
}

// Test accounts data — passwords generated at runtime (never hardcoded)
$testAccounts = [
    ['account_id' => 'yash',      'email' => 'yash@moneyflow.local'],
    ['account_id' => 'rohit',     'email' => 'rohit@moneyflow.local'],
    ['account_id' => 'deependra', 'email' => 'deependra@moneyflow.local'],
    ['account_id' => 'hemang',    'email' => 'hemang@moneyflow.local'],
    ['account_id' => 'manan',     'email' => 'manan@moneyflow.local']
];

echo "=== MoneyFlow Test Account Creator ===\n";
echo "Environment: {$appEnv}\n\n";

// CLI confirmation prompt (safety check)
if (php_sapi_name() === 'cli') {
    echo "This will create test accounts in the database.\n";
    echo "Continue? (y/N): ";
    $handle = fopen("php://stdin", "r");
    $input  = trim(fgets($handle));
    fclose($handle);
    if (strtolower($input) !== 'y') {
        echo "Aborted.\n";
        exit(0);
    }
    echo "\n";
}

$createdAccounts = [];

foreach ($testAccounts as $account) {
    $password = generateSecurePassword(16);
    echo "Creating account: {$account['account_id']}... ";

    $result = createMemberAccount(
        $account['account_id'],
        $account['email'],
        $password
    );

    if ($result['success']) {
        echo "Success (Member ID: {$result['memberId']})\n";
        $createdAccounts[] = [
            'username' => $account['account_id'],
            'password' => $password
        ];
    } else {
        echo "Failed: {$result['errorMsg']}\n";
    }
}

echo "\n=== Test Accounts Created ===\n";
echo "\nCredentials (save these, they won't be shown again):\n";
echo str_repeat('-', 50) . "\n";
foreach ($createdAccounts as $acc) {
    echo "Username: {$acc['username']}, Password: {$acc['password']}\n";
}
echo str_repeat('-', 50) . "\n";
echo "\nEach account starts with Rs.100.00 balance\n";
echo "\nWARNING: Store these credentials securely. They are randomly generated.\n";