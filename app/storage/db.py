# app/storage/db.py
import os
import hashlib
import hmac
import base64
import secrets
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
MONGO_DB  = os.getenv("MONGO_DB", "securechat")

client = MongoClient(MONGO_URI)
db = client[MONGO_DB]
users = db["users"]

def init_indexes():
    # Ensure username and email are unique
    users.create_index("email", unique=True)
    users.create_index("username", unique=True)

def generate_salt() -> bytes:
    return secrets.token_bytes(16)

def hash_password(salt: bytes, password: str) -> str:
    # Return hex SHA256(salt||password)
    data = salt + password.encode("utf-8")
    return hashlib.sha256(data).hexdigest()

def register_user(email: str, username: str, password: str) -> bool:
    # Register a new user, return True on success, False if user exists
    init_indexes()
    salt = generate_salt()
    pwd_hash = hash_password(salt, password)
    try:
        users.insert_one({
            "email": email,
            "username": username,
            "salt": base64.b64encode(salt).decode("ascii"),
            "pwd_hash": pwd_hash,
        })
        return True
    except Exception as e:
        # likely duplicate key error
        print("[!] Registration failed:", e)
        return False

def verify_login(email: str, password: str) -> bool:
    # Check user credentials, return True if valid
    record = users.find_one({"email": email})
    if not record:
        return False
    salt = base64.b64decode(record["salt"])
    expected_hash = record["pwd_hash"]
    computed = hash_password(salt, password)
    return hmac.compare_digest(expected_hash, computed)
