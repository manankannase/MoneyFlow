<?php
require __DIR__ . '/../settings/db_config.php';
$pdo = getDbConnection();
foreach (['CREATE TABLE forbidden (id INT)', 'DELETE FROM transfer_ledger', 'DELETE FROM event_chronicle', 'DROP TABLE members'] as $sql) {
    try { $pdo->exec($sql); throw new RuntimeException('Runtime account has excessive privileges.'); }
    catch (PDOException $e) { if (($e->errorInfo[1] ?? 0) !== 1142) throw $e; }
}
echo "runtime privilege checks passed\n";
