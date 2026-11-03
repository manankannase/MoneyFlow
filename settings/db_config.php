<?php
declare(strict_types=1);

function appSecret(string $name): string {
    $file = getenv($name . '_FILE');
    $value = $file ? @file_get_contents($file) : getenv($name);
    if (!is_string($value) || strlen(trim($value)) < 32 || str_starts_with($value, 'CHANGE_ME')) {
        throw new RuntimeException('Required secret is unavailable.');
    }
    return trim($value);
}

function getDbConnection(): PDO {
    static $pdo;
    if ($pdo instanceof PDO) return $pdo;
    $host = getenv('DATABASE_HOST') ?: 'db';
    $name = getenv('DATABASE_NAME') ?: 'moneyflow_db';
    if (!preg_match('/^[a-zA-Z0-9_.-]+$/D', $host) || !preg_match('/^[a-zA-Z0-9_]+$/D', $name)) {
        throw new RuntimeException('Invalid database configuration.');
    }
    $pdo = new PDO("mysql:host=$host;dbname=$name;charset=utf8mb4", getenv('DATABASE_USER') ?: 'moneyflow_app', appSecret('DATABASE_PASS'), [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
        PDO::ATTR_TIMEOUT => 5,
        PDO::MYSQL_ATTR_MULTI_STATEMENTS => false,
    ]);
    $pdo->exec("SET time_zone = '+00:00', SESSION innodb_lock_wait_timeout = 5");
    if ((int)$pdo->query('SELECT version FROM schema_version')->fetchColumn() !== 2) throw new RuntimeException('Schema migration is required.');
    return $pdo;
}
