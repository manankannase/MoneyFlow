#!/usr/bin/env python3
"""Create local secret files without printing their contents or replacing existing files."""
import os
import secrets
from pathlib import Path
root = Path(__file__).resolve().parents[1]
os.umask(0o077)
directory = root / '.secrets'
directory.mkdir(mode=0o700, exist_ok=True)
for name in ('db_password', 'db_root_password', 'app_key'):
    path = directory / name
    if not path.exists():
        with path.open('x') as stream:
            stream.write(secrets.token_hex(32) + '\n')
        # Compose mounts are read by the non-root PHP worker; parent stays 0700.
        path.chmod(0o444)
print('Local secret files are ready. No existing value was replaced.')
