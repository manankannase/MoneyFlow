<?php
/**
 * Phase 2 Bulk Account Seeder
 *
 * Populates the database with all Phase 2 course accounts in one run.
 * Passwords are hardcoded here for deployment convenience; they are
 * hashed with Argon2id before storage — the plain-text never persists.
 *
 * IMPORTANT: This script is CLI-only. It will refuse to run over HTTP.
 * The per-IP registration rate limit (5/day) does NOT apply here;
 * createMemberAccountAdmin() bypasses it exclusively for this seeder.
 *
 * Usage:
 *   docker exec moneyflow-webserver php /var/www/html/create_accounts.php
 */

// Hard gate — refuse to run if invoked over HTTP.
if (php_sapi_name() !== 'cli') {
    http_response_code(403);
    exit('Forbidden');
}

define('APP_BASE', __DIR__);
require_once APP_BASE . '/utilities/auth.php';

// ---------------------------------------------------------------------------
// Phase 2 accounts — username, email, plaintext password (hashed on insert)
// ---------------------------------------------------------------------------
$accounts = [
    ['cs22btech11022', 'cs22btech11022@iith.ac.in', 'MwLDtUiksy'],
    ['cs22btech11042', 'cs22btech11042@iith.ac.in', 'cUKZvWSkgA'],
    ['cs22btech11054', 'cs22btech11054@iith.ac.in', 'sP284Hegtg'],
    ['cs22btech11055', 'cs22btech11055@iith.ac.in', 'k7BPkyK6id'],
    ['cs22btech11056', 'cs22btech11056@iith.ac.in', 'QpaWGsUb2m'],
    ['cs22btech11059', 'cs22btech11059@iith.ac.in', 'hGntRnqreG'],
    ['cs22btech11061', 'cs22btech11061@iith.ac.in', 'wXQkCQSVCQ'],
    ['cs23btech11006', 'cs23btech11006@iith.ac.in', '1w6kN278Xe'],
    ['cs23btech11018', 'cs23btech11018@iith.ac.in', 'MZRCtQ0Hbo'],
    ['cs23btech11030', 'cs23btech11030@iith.ac.in', 'xrhzzETpyp'],
    ['cs23btech11041', 'cs23btech11041@iith.ac.in', 'gqweH0bhS7'],
    ['cs23btech11044', 'cs23btech11044@iith.ac.in', 'ITz0T1WQhc'],
    ['cs24mtech11012', 'cs24mtech11012@iith.ac.in', 'EprdEWvMtK'],
    ['cs24mtech12001', 'cs24mtech12001@iith.ac.in', 'C73kQDJ7tB'],
    ['cs24mtech12015', 'cs24mtech12015@iith.ac.in', 'BJfjBpy7rf'],
    ['cs24mtech12019', 'cs24mtech12019@iith.ac.in', 'X6fBjoyOTe'],
    ['cs24mtech12021', 'cs24mtech12021@iith.ac.in', 'MNN1fKMJCh'],
    ['cs24mtech14008', 'cs24mtech14008@iith.ac.in', 'VSBz1oBXqV'],
    ['cs24mtech14020', 'cs24mtech14020@iith.ac.in', '4LuJoueFUf'],
    ['cs25mtech11002', 'cs25mtech11002@iith.ac.in', 'fNPIO5Kn8s'],
    ['cs25mtech11003', 'cs25mtech11003@iith.ac.in', 'lh5KBJKvvc'],
    ['cs25mtech11004', 'cs25mtech11004@iith.ac.in', '7TgHO8jwOv'],
    ['cs25mtech11005', 'cs25mtech11005@iith.ac.in', 'SVXlpfKYkj'],
    ['cs25mtech11006', 'cs25mtech11006@iith.ac.in', 'QOxkrHrrXP'],
    ['cs25mtech11007', 'cs25mtech11007@iith.ac.in', 'q4ZTKQXG6o'],
    ['cs25mtech11008', 'cs25mtech11008@iith.ac.in', 'e2pnaRjn9M'],
    ['cs25mtech11009', 'cs25mtech11009@iith.ac.in', 'PgERKrpT8F'],
    ['cs25mtech11010', 'cs25mtech11010@iith.ac.in', 'AN23dCXg6p'],
    ['cs25mtech11011', 'cs25mtech11011@iith.ac.in', 'rGR5NtY8nj'],
    ['cs25mtech11012', 'cs25mtech11012@iith.ac.in', 'mKS6CNwOS6'],
    ['cs25mtech11013', 'cs25mtech11013@iith.ac.in', 'k9ARdyW0zq'],
    ['cs25mtech11014', 'cs25mtech11014@iith.ac.in', 'VDCSrLNmOh'],
    ['cs25mtech11016', 'cs25mtech11016@iith.ac.in', 'mFLhAS8TP5'],
    ['cs25mtech11017', 'cs25mtech11017@iith.ac.in', 'TwDP3xRagR'],
    ['cs25mtech11018', 'cs25mtech11018@iith.ac.in', 'qsRMi90VXL'],
    ['cs25mtech11019', 'cs25mtech11019@iith.ac.in', 'TGDGirJcr6'],
    ['cs25mtech11021', 'cs25mtech11021@iith.ac.in', 'Bat6oYCClb'],
    ['cs25mtech11022', 'cs25mtech11022@iith.ac.in', 'JFTSo0rIBe'],
    ['cs25mtech11023', 'cs25mtech11023@iith.ac.in', 'Iu8hUOEM2V'],
    ['cs25mtech11024', 'cs25mtech11024@iith.ac.in', 'BK76PByTX4'],
    ['cs25mtech11025', 'cs25mtech11025@iith.ac.in', 'bIPKJhvQcn'],
    ['cs25mtech11026', 'cs25mtech11026@iith.ac.in', 'NREAMM3rk7'],
    ['cs25mtech11027', 'cs25mtech11027@iith.ac.in', 'tuGcLFySrN'],
    ['cs25mtech11028', 'cs25mtech11028@iith.ac.in', 'NrxalE3BvK'],
    ['cs25mtech11029', 'cs25mtech11029@iith.ac.in', 'TZwSo6l2sY'],
    ['cs25mtech12015', 'cs25mtech12015@iith.ac.in', 'sv3j7wEIaZ'],
    ['cs25mtech12016', 'cs25mtech12016@iith.ac.in', 'FuSPW9Th19'],
    ['cs25mtech12018', 'cs25mtech12018@iith.ac.in', 'QyYoY1NRr8'],
    ['cs25mtech12019', 'cs25mtech12019@iith.ac.in', 'JNZFtGSxnY'],
    ['cs25mtech12021', 'cs25mtech12021@iith.ac.in', 'OBZkRMV3Uc'],
    ['cs25mtech13001', 'cs25mtech13001@iith.ac.in', 'r9TZ8ZPyIB'],
    ['cs25mtech13002', 'cs25mtech13002@iith.ac.in', 'ZD0so5nvgb'],
    ['cs25mtech13003', 'cs25mtech13003@iith.ac.in', 'Cy2AIANmnJ'],
    ['cs25mtech13004', 'cs25mtech13004@iith.ac.in', 'Y0OeezGWh0'],
    ['cs25mtech13005', 'cs25mtech13005@iith.ac.in', 'WNqb97cN80'],
    ['cs25mtech13006', 'cs25mtech13006@iith.ac.in', 'ErcBBpT0h3'],
    ['cs25mtech13008', 'cs25mtech13008@iith.ac.in', 'IzLWs6cahy'],
    ['cs25mtech13009', 'cs25mtech13009@iith.ac.in', 'KxDFnP2iQN'],
    ['cs25mtech13010', 'cs25mtech13010@iith.ac.in', 'Yy5lFZPWgw'],
    ['cs25mtech13011', 'cs25mtech13011@iith.ac.in', 'DqcNsyHGgM'],
    ['cs25mtech14001', 'cs25mtech14001@iith.ac.in', 'BFnbpVomlD'],
    ['cs25mtech14002', 'cs25mtech14002@iith.ac.in', 'SRYgcfehFM'],
    ['cs25mtech14003', 'cs25mtech14003@iith.ac.in', '1rXYsT4F2a'],
    ['cs25mtech14004', 'cs25mtech14004@iith.ac.in', 'jPk5UTEs8H'],
    ['cs25mtech14005', 'cs25mtech14005@iith.ac.in', 'Hlb0FBZmKz'],
    ['cs25mtech14007', 'cs25mtech14007@iith.ac.in', 'WPUZhsrilQ'],
    ['cs25mtech14009', 'cs25mtech14009@iith.ac.in', 'v5TXYa5ACy'],
    ['cs25mtech14011', 'cs25mtech14011@iith.ac.in', 'XbarOsLRQy'],
    ['cs25mtech14012', 'cs25mtech14012@iith.ac.in', 'WgvqblxZPw'],
    ['cs25mtech14013', 'cs25mtech14013@iith.ac.in', 'k7CHo8f7Fe'],
    ['cs25mtech14014', 'cs25mtech14014@iith.ac.in', 'AOIeEVFdUZ'],
    ['cs25mtech14015', 'cs25mtech14015@iith.ac.in', 'vjEureCBwc'],
    ['cs25mtech14016', 'cs25mtech14016@iith.ac.in', '2gC62SUNPh'],
    ['cs25mtech14017', 'cs25mtech14017@iith.ac.in', 'b4CuVaAY0S'],
    ['cs25mtech14018', 'cs25mtech14018@iith.ac.in', 'pCoVd9UJZ8'],
    ['cs25mtech14019', 'cs25mtech14019@iith.ac.in', '2YnXKCBE4b'],
    ['cs25mtech14020', 'cs25mtech14020@iith.ac.in', 'eUyX8CUPaL'],
    ['cs25mtech14021', 'cs25mtech14021@iith.ac.in', 'i7g51BYx6v'],
    ['cs25mtech14024', 'cs25mtech14024@iith.ac.in', 'm5y0PzGNqG'],
    ['cs25mtech14025', 'cs25mtech14025@iith.ac.in', '5xcalR9aXe'],
    ['cs25mtech14026', 'cs25mtech14026@iith.ac.in', 'JSd7f1nrIl'],
    ['cs25mtech14027', 'cs25mtech14027@iith.ac.in', 'gUIgcbdKC8'],
    ['cs26mtech02004', 'cs26mtech02004@iith.ac.in', 'qESHl6ioR5'],
    ['cs26mtech02007', 'cs26mtech02007@iith.ac.in', 'wFExUKwxMw'],
    ['cs26mtech02008', 'cs26mtech02008@iith.ac.in', 'k8iSlwDzvt'],
    ['cs26mtech02009', 'cs26mtech02009@iith.ac.in', 'l64BAHxNpy'],
    ['cs26mtech02010', 'cs26mtech02010@iith.ac.in', 'AnCt3cyckN'],
    ['cs26resch02001', 'cs26resch02001@iith.ac.in', 'iJe8IYAeeD'],
    ['em25mtech11006', 'em25mtech11006@iith.ac.in', 'HZhu4zBvwc'],
    ['em25mtech11007', 'em25mtech11007@iith.ac.in', 'cYiOWPLbZu'],
    ['em25mtech11008', 'em25mtech11008@iith.ac.in', 'BvcuAzQrB8'],
    ['em25mtech14006', 'em25mtech14006@iith.ac.in', '6GLWiK13e7'],
    ['em25mtech14009', 'em25mtech14009@iith.ac.in', '1aVdA3URjH'],
];

echo "=== MoneyFlow Phase 2 Account Seeder ===\n";
echo "Total accounts to create: " . count($accounts) . "\n\n";

$created = 0;
$skipped = 0;
$failed  = 0;

foreach ($accounts as [$username, $email, $password]) {
    echo "  Creating {$username} ... ";
    $result = createMemberAccountAdmin($username, $email, $password);

    if ($result['success']) {
        echo "OK (ID: {$result['memberId']})\n";
        $created++;
    } elseif (str_contains($result['errorMsg'], 'already registered')) {
        echo "SKIP (already exists)\n";
        $skipped++;
    } else {
        echo "FAIL: {$result['errorMsg']}\n";
        $failed++;
    }
}

echo "\n=== Done ===\n";
echo "Created : {$created}\n";
echo "Skipped : {$skipped} (already existed)\n";
echo "Failed  : {$failed}\n";
echo "\nAll accounts start with Rs.100.00 balance.\n";
?>
