# create_test_user.py

from app.storage.db import register_user

email = "armas@ymail.com"
username = "armas"
password = "12345"

print("[*] Creating user...")
ok = register_user(email, username, password)

if ok:
    print("[+] User created:")
    print(f"    email={email}")
    print(f"    username={username}")
    print(f"    password={password}")
else:
    print("[!] Failed to create user (possibly already exists)")
