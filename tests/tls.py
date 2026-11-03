#!/usr/bin/env python3
"""Verify the production proxy boundary with an explicit local test CA."""
import argparse, http.cookiejar, re, secrets, ssl, urllib.request, urllib.parse, urllib.error
p=argparse.ArgumentParser(); p.add_argument('--ca',default='runtime/test-root.crt');p.add_argument('--url',default='https://localhost:18443');a=p.parse_args()
ctx=ssl.create_default_context(cafile=a.ca)
jar=http.cookiejar.CookieJar()
opener=urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), urllib.request.HTTPCookieProcessor(jar))
def request(path,data=None,headers=None):
    req=urllib.request.Request(a.url+path,urllib.parse.urlencode(data).encode() if data is not None else None,{'User-Agent':'MoneyFlow-TLS-tests',**(headers or {})})
    try: r=opener.open(req,timeout=10)
    except urllib.error.HTTPError as e: r=e
    with r: return r.status,r.read().decode(),r.headers
code,body,headers=request('/register.php')
assert code==200,(code,body)
assert 'secure' in headers['Set-Cookie'].lower() and 'HttpOnly' in headers['Set-Cookie'] and 'SameSite=Strict' in headers['Set-Cookie']
assert headers.get('Strict-Transport-Security')
token=re.search(r'name="csrf_token" value="([a-f0-9]{64})"',body).group(1)
name='tls_'+secrets.token_hex(4);password='PrivateTest1!'+secrets.token_hex(8)
code,body,_=request('/register.php',{'csrf_token':token,'account_id':name,'email':name+'@example.test','password':password,'confirm_password':password})
assert code==200 and 'Account created successfully' in body
code,body,_=request('/login.php');token=re.search(r'name="csrf_token" value="([a-f0-9]{64})"',body).group(1)
code,body,_=request('/login.php',{'csrf_token':token,'account_id':name,'password':password})
assert code==200 and 'Current Balance' in body,(code,body[:200])
assert next(c for c in jar if c.name=='mf_session').secure
code,body,_=request('/dashboard.php',headers={'X-Forwarded-For':'203.0.113.9','X-Forwarded-Proto':'http'})
assert code==200 and 'Current Balance' in body,(code,body[:200])
assert request('/profile.php',{}, {'Origin':'https://evil.example'})[0]==403
print('TLS certificate, secure cookies, origin checks and trusted proxy checks passed')
