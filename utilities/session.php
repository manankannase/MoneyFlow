<?php
declare(strict_types=1);
require_once __DIR__ . '/security.php';
require_once __DIR__ . '/activity_log.php';
const SESSION_COOKIE_NAME = 'mf_session';
const SESSION_LIFETIME_SECONDS = 28800;
const SESSION_IDLE_SECONDS = 1800;

function createSession(int $memberId): string {
    $raw = bin2hex(random_bytes(32));
    $pdo = getDbConnection();
    $pdo->beginTransaction();
    try {
        // Rotate an existing browser session before issuing a new bearer token.
        $old = $_COOKIE[SESSION_COOKIE_NAME] ?? '';
        $s = $pdo->prepare('DELETE FROM member_sessions WHERE token_hash = ?');
        $s->execute([hash('sha256', is_string($old) ? $old : '')]);
        $s = $pdo->prepare('INSERT INTO member_sessions (member_id, token_hash, csrf_token, agent_hash, ip_address, expires_at, last_seen) VALUES (?, ?, ?, ?, ?, ?, UTC_TIMESTAMP())');
        $s->execute([$memberId, hash('sha256', $raw), bin2hex(random_bytes(32)), hash('sha256', $_SERVER['HTTP_USER_AGENT'] ?? ''), getClientIp(), gmdate('Y-m-d H:i:s', time() + SESSION_LIFETIME_SECONDS)]);
        $pdo->commit();
    } catch (Throwable $e) { if ($pdo->inTransaction()) $pdo->rollBack(); throw $e; }
    setcookie(SESSION_COOKIE_NAME, $raw, cookieOptions(time() + SESSION_LIFETIME_SECONDS));
    setcookie('mf_preauth', '', cookieOptions(time() - 3600));
    return $raw;
}

function validateSession(): ?array {
    $raw = $_COOKIE[SESSION_COOKIE_NAME] ?? '';
    if (!is_string($raw) || !preg_match('/^[a-f0-9]{64}$/D', $raw)) return null;
    $pdo = getDbConnection();
    $s = $pdo->prepare('SELECT s.id, s.member_id, s.csrf_token, s.agent_hash, s.ip_address, m.account_name, m.email_address, m.account_balance, m.member_bio, m.profile_photo FROM member_sessions s JOIN members m ON m.id = s.member_id WHERE s.token_hash = ? AND s.expires_at > UTC_TIMESTAMP() AND s.last_seen > DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1800 SECOND)');
    $s->execute([hash('sha256', $raw)]);
    $row = $s->fetch();
    if (!$row) return null;
    if (!hash_equals($row['agent_hash'], hash('sha256', $_SERVER['HTTP_USER_AGENT'] ?? '')) || $row['ip_address'] !== getClientIp()) {
        destroySession($raw); return null;
    }
    $s = $pdo->prepare('UPDATE member_sessions SET last_seen = UTC_TIMESTAMP() WHERE id = ?');
    $s->execute([$row['id']]);
    return $row;
}

function destroySession(?string $rawToken = null): void {
    $rawToken ??= $_COOKIE[SESSION_COOKIE_NAME] ?? '';
    if (is_string($rawToken)) {
        $s = getDbConnection()->prepare('DELETE FROM member_sessions WHERE token_hash = ?');
        $s->execute([hash('sha256', $rawToken)]);
    }
    setcookie(SESSION_COOKIE_NAME, '', cookieOptions(time() - 3600));
}

function validateCsrfToken(string $submitted, string $expected): bool {
    return strlen($expected) === 64 && strlen($submitted) === 64 && hash_equals($expected, $submitted);
}
