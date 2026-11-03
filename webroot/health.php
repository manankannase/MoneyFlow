<?php
require_once __DIR__ . '/../settings/db_config.php';
header('Content-Type: text/plain');
header('Cache-Control: no-store');
try {
    if ((int)getDbConnection()->query('SELECT version FROM schema_version')->fetchColumn() !== 2) throw new RuntimeException();
    echo 'ok';
} catch (Throwable $e) { http_response_code(503); echo 'unavailable'; }
