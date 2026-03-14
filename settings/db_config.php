<?php
/**
 * Database Configuration and Connection Management
 * 
 * Utilizes PDO with parameterized queries to prevent injection attacks.
 * All database interactions across the application MUST employ parameterized queries.
 */

define('DATABASE_HOST', getenv('DATABASE_HOST') ?: 'db');
define('DATABASE_NAME', getenv('DATABASE_NAME') ?: 'moneyflow_db');
define('DATABASE_USER', getenv('DATABASE_USER') ?: 'moneyflow_admin');

// FIX V4: No hardcoded fallback password. If DATABASE_PASS is not set, fail hard.
// Opponents receive your source code; any fallback is immediately known to them.
$_dbPassCheck = getenv('DATABASE_PASS');
if (!$_dbPassCheck) {
    error_log('FATAL: DATABASE_PASS environment variable is not set.');
    exit('Server configuration error.');
}
define('DATABASE_PASS', $_dbPassCheck);
unset($_dbPassCheck);
define('DATABASE_CHARSET', 'utf8mb4');

/**
 * Retrieve PDO database connection instance.
 * Implements singleton pattern to maintain a single connection throughout application lifecycle.
 *
 * Security Features: PDO configured with ERRMODE_EXCEPTION and EMULATE_PREPARES disabled
 * This ensures native prepared statements are used, providing robust protection 
 * against SQL injection attacks.
 *
 * @return PDO Database connection instance
 */
function getPDOConnection(): PDO {
    static $dbConn = null;

    if ($dbConn === null) {
        $connectionString = sprintf(
            'mysql:host=%s;dbname=%s;charset=%s',
            DATABASE_HOST,
            DATABASE_NAME,
            DATABASE_CHARSET
        );

        $pdoOptions = [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            // CRITICAL: Disable emulated prepares to use native prepared statements
            // This ensures database engine handles parameter binding securely
            PDO::ATTR_EMULATE_PREPARES   => false,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            // Prevent stacked query injection attacks
            PDO::MYSQL_ATTR_MULTI_STATEMENTS => false,
        ];

        try {
            $dbConn = new PDO($connectionString, DATABASE_USER, DATABASE_PASS, $pdoOptions);
        } catch (PDOException $error) {
            // CRITICAL: Don't expose database error details to end users
            error_log('Database connection error: ' . $error->getMessage());
            exit('A database service error occurred. Please try again later.');
        }
    }

    return $dbConn;
}
?>
