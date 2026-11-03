<?php
require __DIR__ . '/../utilities/validation.php';
require __DIR__ . '/../utilities/security.php';
function check(bool $condition, string $label): void { if (!$condition) throw new RuntimeException($label); }
foreach (['0','-1','1.001','1e2','NaN','INF','01',' 1','1 ','.10','9999999',[],1.0,null] as $bad) check(!validateAmount($bad), 'invalid amount accepted');
foreach (['0.01','1','12.3','999999.99'] as $good) check(validateAmount($good), 'valid amount rejected');
check(amountToMinor('10.29') === 1029 && minorToAmount(1029) === '10.29', 'decimal round trip');
check(minorToAmount(amountToMinor('0.10') + amountToMinor('0.20')) === '0.30', 'exact arithmetic');
check(validatePassword('LongEnough1!') && !validatePassword(str_repeat('A',73)) && !validatePassword("LongEnough1!\0"), 'bcrypt boundaries');
check(!validateMemo("memo\0") && h('<script>') === '&lt;script&gt;', 'output and memo validation');
$_SERVER['REMOTE_ADDR']='127.0.0.1'; $_SERVER['HTTP_X_FORWARDED_FOR']='8.8.8.8';
check(getClientIp() === '127.0.0.1', 'forwarding spoof');
echo "unit assertions passed\n";
