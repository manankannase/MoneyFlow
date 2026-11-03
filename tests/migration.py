#!/usr/bin/env python3
import argparse, pathlib, secrets, shutil, subprocess
p=argparse.ArgumentParser();p.add_argument('--project',required=True);a=p.parse_args()
cmd=['docker-compose'] if shutil.which('docker-compose') else ['docker','compose']
def sql(text):
    r=subprocess.run(cmd+['-p',a.project,'exec','-T','db','sh','-c','MYSQL_PWD="$(cat /run/secrets/db_root_password)" mysql -uroot -N'],input=text,text=True,capture_output=True,check=True)
    return r.stdout.strip()
name='moneyflow_migration_'+secrets.token_hex(6)
root=pathlib.Path(__file__).resolve().parents[1]
try:
    sql((root/'tests/v1-schema.sql').read_text().replace('moneyflow_db',name))
    sql(f"USE {name}; INSERT INTO members (account_name,email_address,password_hash,account_balance) VALUES ('alice','alice@example.test','unused',90),('bob','bob@example.test','unused',110); INSERT INTO transfer_ledger(sender_id,recipient_id,transfer_amount,memo_text) VALUES(1,2,10,'legacy');")
    sql((root/'deploy/migrate-v1-to-v2.sql').read_text().replace('moneyflow_db',name))
    assert sql(f'USE {name}; SELECT version FROM schema_version;')=='2'
    assert sql(f'USE {name}; SELECT SUM(account_balance) FROM members;')=='200.00'
    assert sql(f'USE {name}; SELECT COUNT(*) FROM transfer_ledger WHERE LENGTH(idempotency_key)=64;')=='1'
    print('v1 migration preserves balances and ledger rows')
finally:
    sql(f'DROP DATABASE IF EXISTS {name};')
