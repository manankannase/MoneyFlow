<?php
declare(strict_types=1);
require_once __DIR__ . '/security.php';

function auditEvent(string $event, ?int $memberId = null, ?PDO $pdo = null): void {
    $pdo ??= getDbConnection();
    $stmt = $pdo->prepare('INSERT INTO event_chronicle (member_id, event_type, ip_hash) VALUES (?, ?, ?)');
    $stmt->execute([$memberId, $event, hash_hmac('sha256', getClientIp(), appSecret('HMAC_SECRET'))]);
    error_log(json_encode(['event' => $event, 'member_id' => $memberId]));
}

function logPageAccess(?int $memberId, ?string $accountName): void {
    // Read-only page views go to the web access log; mutations are recorded in SQL.
}

// Reserve attempts before expensive hashing. MySQL serializes each counter update.
function consumeRateLimit(string $scope, string $identity, int $limit, int $window = 900): bool {
    $pdo = getDbConnection();
    $key = hash_hmac('sha256', "$scope:$identity", appSecret('HMAC_SECRET'));
    $bucket = intdiv(time(), $window);
    $pdo->beginTransaction();
    try {
        $s = $pdo->prepare('INSERT INTO request_limits (bucket_key, bucket, attempts) VALUES (?, ?, 0) ON DUPLICATE KEY UPDATE bucket_key = bucket_key');
        $s->execute([$key, $bucket]);
        $s = $pdo->prepare('SELECT attempts FROM request_limits WHERE bucket_key = ? AND bucket = ? FOR UPDATE');
        $s->execute([$key, $bucket]);
        $allowed = (int)$s->fetchColumn() < $limit;
        if ($allowed) {
            $s = $pdo->prepare('UPDATE request_limits SET attempts = attempts + 1 WHERE bucket_key = ? AND bucket = ?');
            $s->execute([$key, $bucket]);
        }
        $pdo->commit();
        return $allowed;
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        throw $e; // A broken limiter must not grant unrestricted access.
    }
}
