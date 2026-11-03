<?php
declare(strict_types=1);
require_once __DIR__ . '/../settings/db_config.php';
date_default_timezone_set('UTC');

set_exception_handler(function (Throwable $e): void {
    $id = bin2hex(random_bytes(8));
    error_log(json_encode(['event' => 'request_failed', 'id' => $id, 'type' => get_class($e)]));
    http_response_code(503);
    header('Content-Type: text/plain; charset=UTF-8');
    header('Cache-Control: no-store');
    echo 'Service temporarily unavailable. Reference: ' . $id;
});

function sendSecurityHeaders(): void {
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header("Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
    header('Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()');
    header('Cache-Control: no-store');
    if (getenv('APP_ENV') !== 'development') header('Strict-Transport-Security: max-age=31536000');
    // Apache owns the proxy boundary. Client-supplied forwarding headers are ignored.
    if (getenv('APP_ENV') !== 'development' && ($_SERVER['HTTPS'] ?? '') !== 'on') {
        http_response_code(400); exit('HTTPS is required.');
    }
    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    if (!in_array($method, ['GET', 'POST'], true)) {
        header('Allow: GET, POST'); http_response_code(405); exit('Method not allowed.');
    }
    foreach ([$_GET, $_POST] as $data) {
        foreach ($data as $value) {
            if (!is_string($value) || strlen($value) > 4096) {
                http_response_code(400); exit('Invalid input.');
            }
        }
    }
    if ($method === 'POST') {
        $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
        if ($origin !== '' && !hash_equals(getenv('APP_ORIGIN') ?: '', $origin)) {
            http_response_code(403); exit('Invalid request origin.');
        }
        $type = strtolower(explode(';', $_SERVER['CONTENT_TYPE'] ?? '')[0]);
        if (!in_array($type, ['application/x-www-form-urlencoded', 'multipart/form-data'], true)) {
            http_response_code(415); exit('Unsupported request body.');
        }
    }
}

function getClientIp(): string {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '';
    return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '0.0.0.0';
}

function cookieOptions(int $expiry): array {
    return ['expires' => $expiry, 'path' => '/', 'secure' => getenv('APP_ENV') !== 'development', 'httponly' => true, 'samesite' => 'Strict'];
}

function preauthCsrf(bool $create = false): string {
    $cookie = $_COOKIE['mf_preauth'] ?? '';
    if (!is_string($cookie) || !preg_match('/^[a-f0-9]{64}:[0-9]{10}$/D', $cookie)
        || (int)substr($cookie, 65) < time() - 900 || (int)substr($cookie, 65) > time()) {
        if (!$create) return '';
        $cookie = bin2hex(random_bytes(32)) . ':' . time();
        setcookie('mf_preauth', $cookie, cookieOptions(time() + 900));
        $_COOKIE['mf_preauth'] = $cookie;
    }
    return hash_hmac('sha256', $cookie, appSecret('HMAC_SECRET'));
}

function checkPreauthCsrf(): void {
    $expected = preauthCsrf();
    if ($expected === '' || !hash_equals($expected, $_POST['csrf_token'] ?? '')) {
        http_response_code(403); exit('Invalid request token. Reload the form.');
    }
}
