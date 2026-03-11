<?php
/**
 * Database Configuration
 *
 * Returns a PDO connection using environment variables.
 * Never hardcode credentials here.
 */

function getDbConnection(): PDO {
    $host    = getenv('DATABASE_HOST') ?: 'db';
    $dbname  = getenv('DATABASE_NAME') ?: 'moneyflow_db';
    $user    = getenv('DATABASE_USER') ?: '';
    $pass    = getenv('DATABASE_PASS') ?: '';

    if (empty($user) || empty($pass)) {
        error_log('MoneyFlow: DATABASE_USER or DATABASE_PASS environment variable is not set.');
        throw new RuntimeException('Database credentials are not configured.');
    }

    $dsn = "mysql:host={$host};dbname={$dbname};charset=utf8mb4";

    $options = [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,   // real prepared statements
        PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci",
    ];

    return new PDO($dsn, $user, $pass, $options);
}
