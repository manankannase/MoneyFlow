<?php
/**
 * Test Account Creator Script
 * Creates sample member accounts for testing
 *
 * Usage: docker exec moneyflow-webserver php /var/www/html/create_accounts.php
 *
 * SECURITY: This script should only be run in development environments.
 */

define('APP_BASE', __DIR__);

require_once APP_BASE . '/utilities/auth.php';

// ----------------------------------------------------------------
// Environment Check: Only allow in development
// ----------------------------------------------------------------
$appEnv = getenv('APP_ENV') ?: 'production';
if ($appEnv === 'production') {
    echo "ERROR: This script cannot be run in a production environment.\n";
    echo "Set APP_ENV=development in your .env file to use this script.\n";
    exit(1);
}

// ----------------------------------------------------------------
// Confirmation Prompt (safety check)
// ----------------------------------------------------------------
if (php_sapi_name() === 'cli') {
    echo "=== MoneyFlow Test Account Creator ===\n";
    echo "Environment: {
    "$appEnv\n\n";
    echo "This will create test accounts in the database.\n";
    echo "Continue? (y/N): ";
    $handle = fopen("php://stdin", "r");
    $input = trim(fgets($handle));
    fclose($handle);
    if (strtolower($input) !== 'y') {
        echo "Aborted.\n";
        exit(0);
    }
    echo "\n";
}

// Test accounts data
$testAccounts = [
    [
        'account_id' => 'yash',
        'email'      => 'yash@moneyflow.local',
        'password'   => 'Yash@Password101'
    ],
    [
        'account_id' => 'rohit',
        'email'      => 'rohit@moneyflow.local',
        'password'   => 'Rohit@Password102'
    ],
    [
        'account_id' => 'deependra',
        'email'      => 'deependra@moneyflow.local',
        'password'   => 'Deependra@Password103'
    ],
    [
        'account_id' => 'hemang',
        'email'      => 'hemang@moneyflow.local',
        'password'   => 'Hemang@Password104'
    ],
    [
        'account_id' => 'manan',
        'email'      => 'manan@moneyflow.local',
        'password'   => 'Manan@Password105'
    ]
];

echo "Creating test accounts...\n\n";

$successCount = 0;
$failCount = 0;

foreach ($testAccounts as $account) {
    echo "  Creating account: {
    "$account['account_id']}... ";

    $result = createMemberAccount(
        $account['account_id'],
        $account['email'],
        $account['password']
    );

    if ($result['success']) {
        echo "Success (Member ID: {
    "$result['memberId']})\n";
        $successCount++;
    } else {
        echo "Failed: {
    "$result['errorMsg']}\n";
        $failCount++;
    }
}

echo "\n=== Summary ===\n";
echo "Created: {$successCount} | Failed: {$failCount}\n\n";

// SECURITY: Do NOT print passwords to console output.
echo "Test accounts created. See .env.example or project documentation for credentials.\n";
echo "Each account starts with Rs.100.00 balance.\n";