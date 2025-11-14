# app/common/utils.py
import base64
import time
import hmac
import hashlib
from typing import Tuple

def b64encode(data: bytes) -> str:
    # Return URL-safe base64 (no newline) string from bytes
    return base64.b64encode(data).decode("ascii")

def b64decode(data_b64: str) -> bytes:
    # Return bytes from base64 string
    return base64.b64decode(data_b64.encode("ascii"))

def now_ms() -> int:
    # Return current time in milliseconds
    return int(time.time() * 1000)

def sha256_hex(data: bytes) -> str:
    # Return hex SHA-256 digest of data (lowercase)
    return hashlib.sha256(data).hexdigest()

def sha256_bytes(data: bytes) -> bytes:
    # Return raw SHA-256 digest bytes
    return hashlib.sha256(data).digest()

def constant_time_compare(a: str, b: str) -> bool:
    # Constant-time compare for two ASCII strings (hex digests etc.)
    return hmac.compare_digest(a, b)

def make_sig_input(seqno: int, ts: int, ct_bytes: bytes) -> bytes:
    # Build canonical byte string to hash/sign for messages
    seq_bytes = seqno.to_bytes(8, "big", signed=False)
    ts_bytes = ts.to_bytes(8, "big", signed=False)
    return seq_bytes + ts_bytes + ct_bytes

def cert_fingerprint_sha256_der(cert_der_bytes: bytes) -> str:
    # Fingerprint (hex) of a certificate given DER bytes (SHA-256)
    return hashlib.sha256(cert_der_bytes).hexdigest()
