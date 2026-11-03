#!/usr/bin/env python3
"""Exercise the shipped HTTP interface and isolated MySQL database. Uses only test accounts."""
import argparse
import concurrent.futures
import http.cookiejar
import json
import re
import secrets
import shutil
import subprocess
import unittest
import urllib.error
import urllib.parse
import urllib.request

parser = argparse.ArgumentParser()
parser.add_argument('--url', default='http://127.0.0.1:18080')
parser.add_argument('--project', default='moneyflow-secure')
args, remaining = parser.parse_known_args()
PASSWORD = 'TestOnly-' + secrets.token_hex(10) + '!1aA'

class Client:
    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
    def request(self, path, data=None, headers=None):
        headers = {'User-Agent':'MoneyFlow-security-tests', **(headers or {})}
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        req = urllib.request.Request(args.url + path, body, headers)
        try:
            response = self.opener.open(req, timeout=20)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, response.read().decode(errors='replace'), response.headers
    def token(self, path):
        code, body, _ = self.request(path)
        assert code == 200, (code, body[:200])
        return re.search(r'name="csrf_token" value="([a-f0-9]{64})"',body).group(1)
    def login(self, name):
        return self.request('/login.php', {'csrf_token':self.token('/login.php'), 'account_id':name, 'password':PASSWORD})

def sql(statement):
    # Administrator access is confined to this named disposable Compose database.
    result = subprocess.run((['docker-compose'] if shutil.which('docker-compose') else ['docker','compose'])+['-p',args.project,'exec','-T','db','sh','-c',
        'MYSQL_PWD="$(cat /run/secrets/db_root_password)" mysql -uroot -N moneyflow_db'],
        input=statement, text=True, capture_output=True, check=True)
    return result.stdout.strip()

class SecurityIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        assert sql('SELECT VERSION();').startswith('8.')
        sql('DELETE FROM request_limits;')
        cls.a = 'sender_' + secrets.token_hex(4)
        cls.b = 'receiver_' + secrets.token_hex(4)
        cls.c = 'observer_' + secrets.token_hex(4)
        for name in (cls.a, cls.b, cls.c):
            c = Client()
            code, body, _ = c.request('/register.php', {'csrf_token': c.token('/register.php'), 'account_id':name, 'email':name+'@example.test', 'password':PASSWORD,'confirm_password':PASSWORD})
            assert code == 200 and 'Account created successfully' in body, (code, body[:250])
        cls.client = Client()
        code, body, _ = cls.client.login(cls.a)
        assert code == 200 and 'Dashboard' in body, (code, body[:250])
        cls.csrf = cls.client.token('/transfer.php')
        cls.sender_id = int(sql(f"SELECT id FROM members WHERE account_name='{cls.a}';"))
        cls.receiver_id = int(sql(f"SELECT id FROM members WHERE account_name='{cls.b}';"))
        cls.observer_id = int(sql(f"SELECT id FROM members WHERE account_name='{cls.c}';"))

    def transfer(self, amount='1.00', key=None, **extra):
        return self.client.request('/transfer.php', {'csrf_token':self.csrf,'request_id':key or secrets.token_hex(32), 'recipient':self.b,'amount':amount,'memo':'test','password':PASSWORD,**extra})

    def test_01_input_and_csrf(self):
        self.assertEqual(self.transfer(csrf_token='')[0],403)
        self.assertEqual(self.client.request('/profile.php',{'action':'update_profile'})[0],403)
        self.assertEqual(Client().request('/login.php',{'account_id':self.a,'password':PASSWORD})[0],403)
        self.assertEqual(Client().request('/register.php',{})[0],403)
        self.assertEqual(self.client.request('/transfer.php',{'csrf_token[]':'x'})[0],400)
        self.assertEqual(self.client.request('/transfer.php',{}, {'Origin':'https://evil.example'})[0],403)
        self.assertEqual(self.client.request('/logout.php')[0],405)
        self.assertEqual(Client().request('/avatar.php?file=../../.env')[0],401)
        for path in ('/.env','/init.sql','/settings/db_config.php','/.git/config'):
            self.assertIn(self.client.request(path)[0],(403,404))

    def test_02_password_confirmation(self):
        _, body, _ = self.transfer(password='WrongPassword1!')
        self.assertIn('Password confirmation failed',body)
        self.assertEqual(sql(f'SELECT COUNT(*) FROM transfer_ledger WHERE sender_id={self.sender_id};'),'0')

    def test_03_exact_transfer_and_replay(self):
        key = secrets.token_hex(32)
        for _ in range(2):
            code, body, _ = self.transfer('0.10',key)
            self.assertEqual(code,200); self.assertIn('Transfer recorded.',body)
        self.assertEqual(sql(f'SELECT account_balance FROM members WHERE id={self.sender_id};'),'99.90')
        self.assertEqual(sql(f'SELECT COUNT(*) FROM transfer_ledger WHERE sender_id={self.sender_id};'),'1')
        self.assertIn('already used',self.transfer('0.20',key)[1])

    def test_04_parallel_spending(self):
        def send(_):
            c=Client()
            # Independent HTTP clients copy the same established session credentials.
            for cookie in self.client.jar: c.jar.set_cookie(cookie)
            return c.request('/transfer.php', {'csrf_token':self.csrf, 'request_id':secrets.token_hex(32),'recipient':self.b,'amount':'60.00','memo':'parallel','password':PASSWORD})
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(send,range(2)))
        self.assertEqual(sum('Transfer recorded.' in body for _,body,_ in results),1)
        self.assertEqual(sql(f'SELECT account_balance FROM members WHERE id={self.sender_id};'),'39.90')
        self.assertEqual(sql(f'SELECT SUM(account_balance) FROM members WHERE id IN ({self.sender_id},{self.receiver_id});'),'200.00')

    def test_05_failures_and_isolation(self):
        self.assertIn('Invalid transfer',self.transfer('1e2')[1])
        self.assertIn('Choose another',self.transfer(recipient=self.a)[1])
        observer=Client();observer.login(self.c)
        self.assertNotIn('parallel',observer.request('/history.php')[1])
        code,body,headers=self.client.request('/history.php')
        self.assertEqual(code,200);self.assertIn('parallel',body)
        self.assertEqual(headers['X-Content-Type-Options'],'nosniff')
        self.assertIn("frame-ancestors 'none'",headers['Content-Security-Policy'])
        rows=sql('SELECT token_hash FROM member_sessions;').splitlines()
        raw=next(c.value for c in self.client.jar if c.name=='mf_session')
        self.assertNotIn(raw,rows)

    def test_06_logout_and_expiry(self):
        c=Client();c.login(self.b)
        token=c.token('/profile.php')
        code,_,_=c.request('/logout.php',{'csrf_token':token})
        self.assertEqual(code,200)
        self.assertIn('Sign In',c.request('/dashboard.php')[1])
        c.login(self.b)
        sql(f"UPDATE member_sessions SET last_seen=DATE_SUB(UTC_TIMESTAMP(), INTERVAL 31 MINUTE) WHERE member_id={self.receiver_id};")
        self.assertIn('Sign In',c.request('/dashboard.php')[1])

    def test_07_forwarding_spoof_and_sql_injection(self):
        code,body,_=self.client.request('/dashboard.php',headers={'X-Forwarded-For':'8.8.8.8','X-Forwarded-Proto':'https'})
        self.assertEqual(code,200);self.assertIn('Dashboard',body)
        c=Client();code,body,_=c.request('/login.php', {'csrf_token':c.token('/login.php'),'account_id':"' OR 1=1 --",'password':PASSWORD})
        self.assertIn('Invalid credentials',body)
        # Database-stored text must be escaped at every rendering point.
        code,_,_=self.client.request('/profile.php',{'csrf_token':self.csrf,'action':'update_profile','bio':'<script>alert(1)</script>','email':self.a+'@example.test'})
        self.assertEqual(code,200)
        self.assertNotIn('<script>alert(1)</script>',self.client.request('/profile.php')[1])
        self.assertIn('&lt;script&gt;',self.client.request('/profile.php')[1])

    def test_08_atomic_rollback(self):
        sql("CREATE TRIGGER test_ledger_failure BEFORE INSERT ON transfer_ledger FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='injected test failure';")
        before=sql(f'SELECT account_balance FROM members WHERE id={self.sender_id};')
        try:
            self.assertIn('could not be confirmed',self.transfer('1.00')[1])
            self.assertEqual(sql(f'SELECT account_balance FROM members WHERE id={self.sender_id};'),before)
        finally: sql('DROP TRIGGER test_ledger_failure;')

    def test_09_same_second_transfers_and_parallel_replay(self):
        sql('DELETE FROM request_limits;')
        for _ in range(2): self.assertIn('Transfer recorded.',self.transfer('1.01')[1])
        key=secrets.token_hex(32)
        before=int(sql(f'SELECT COUNT(*) FROM transfer_ledger WHERE sender_id={self.sender_id};'))
        def send(_):
            c=Client()
            for cookie in self.client.jar: c.jar.set_cookie(cookie)
            return c.request('/transfer.php',{'csrf_token':self.csrf,'request_id':key,'recipient':self.b,'amount':'0.11','memo':'replay','password':PASSWORD})
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool: results=list(pool.map(send,range(2)))
        self.assertTrue(all('Transfer recorded.' in body for _,body,_ in results))
        self.assertEqual(int(sql(f'SELECT COUNT(*) FROM transfer_ledger WHERE sender_id={self.sender_id};')),before+1)

    def test_09b_opposing_transfers(self):
        sql('DELETE FROM request_limits;')
        receiver=Client(); receiver.login(self.b)
        receiver_csrf=receiver.token('/transfer.php')
        total=sql(f'SELECT SUM(account_balance) FROM members WHERE id IN ({self.sender_id},{self.receiver_id});')
        jobs=[(self.client,self.csrf,self.b),(receiver,receiver_csrf,self.a)]
        def send(job):
            client,csrf,recipient=job
            return client.request('/transfer.php',{'csrf_token':csrf,'request_id':secrets.token_hex(32),'recipient':recipient,'amount':'0.01','memo':'opposing','password':PASSWORD})
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool: results=list(pool.map(send,jobs))
        self.assertTrue(all('Transfer recorded.' in body for _,body,_ in results))
        self.assertEqual(sql(f'SELECT SUM(account_balance) FROM members WHERE id IN ({self.sender_id},{self.receiver_id});'),total)

    def test_10_avatar_reencoding_and_access(self):
        import struct, zlib
        def upload(payload,filename):
            boundary='mf-'+secrets.token_hex(12)
            pieces=[]
            for name,value in [('csrf_token',self.csrf),('action','upload_avatar')]:
                pieces.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode())
            pieces.append(f'--{boundary}\r\nContent-Disposition: form-data; name="avatar"; filename="{filename}"\r\nContent-Type: image/png\r\n\r\n'.encode()+payload+f'\r\n--{boundary}--\r\n'.encode())
            req=urllib.request.Request(args.url+'/profile.php',b''.join(pieces),{'User-Agent':'MoneyFlow-security-tests','Content-Type':'multipart/form-data; boundary='+boundary})
            with self.client.opener.open(req) as response: return response.read().decode()
        self.assertIn('Use a JPEG',upload(b'<?php echo "bad"; ?>','evil.png'))
        def chunk(kind,data): return struct.pack('>I',len(data))+kind+data+struct.pack('>I',zlib.crc32(kind+data))
        png=b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>IIBBBBB',1,1,8,2,0,0,0))+chunk(b'IDAT',zlib.compress(b'\0\xff\0\0'))+chunk(b'IEND',b'')
        self.assertIn('Profile photo updated',upload(png+b'<?php echo "injected"; ?>','avatar.php.png'))
        name=sql(f'SELECT profile_photo FROM members WHERE id={self.sender_id};')
        self.assertRegex(name,r'^[a-f0-9]{64}\.png$')
        code,body,headers=self.client.request('/avatar.php?file='+name)
        self.assertEqual(code,200);self.assertEqual(headers['Content-Type'],'image/png')
        self.assertNotIn('injected',body)
        self.assertEqual(Client().request('/avatar.php?file='+name)[0],401)
        self.assertEqual(self.client.request('/avatar.php?file=../settings/db_config.php')[0],404)

    def test_11_expiry_and_user_agent_binding(self):
        c=Client();c.login(self.c)
        self.assertIn('Sign In',c.request('/dashboard.php',headers={'User-Agent':'different'})[1])
        c.login(self.c)
        sql(f'UPDATE member_sessions SET expires_at=DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 SECOND) WHERE member_id={self.observer_id};')
        self.assertIn('Sign In',c.request('/dashboard.php')[1])

    def test_12_rate_limit_cannot_be_spoofed(self):
        c=Client();token=c.token('/login.php')
        codes=[]
        for i in range(11):
            code,_,_=c.request('/login.php',{'csrf_token':token,'account_id':'absent_fixed','password':'WrongPassword1!'}, {'X-Forwarded-For':f'192.0.2.{i+1}'})
            codes.append(code)
        self.assertIn(429,codes)

if __name__=='__main__': unittest.main(argv=['integration.py',*remaining],verbosity=2)
