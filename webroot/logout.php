<?php
require_once __DIR__ . '/../utilities/session.php';
sendSecurityHeaders();
$session = validateSession();
if ($_SERVER['REQUEST_METHOD'] !== 'POST') { header('Allow: POST'); http_response_code(405); exit('Use the sign-out form.'); }
if (!$session || !validateCsrfToken($_POST['csrf_token'] ?? '', $session['csrf_token'])) { http_response_code(403); exit('Invalid request.'); }
auditEvent('logout', (int)$session['member_id']);
destroySession();
header('Location: /login.php', true, 303);
