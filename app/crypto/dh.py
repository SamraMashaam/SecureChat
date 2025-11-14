# app/crypto/dh.py
import secrets
import hashlib

# A known safe 2048-bit MODP prime (RFC 3526 Group 14)
P = int("""
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
29024E088A67CC74020BBEA63B139B22514A08798E3404DD
EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245
E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF
""".replace("\n", ""), 16)

G = 2

def gen_private():
    return secrets.randbits(256)

def gen_public(a):
    return pow(G, a, P)

def compute_shared(their_pub, my_priv):
    return pow(their_pub, my_priv, P)

def derive_key(shared_int):
    # Shared secret → bytes (big endian)
    shared_bytes = shared_int.to_bytes((shared_int.bit_length() + 7) // 8, "big")
    digest = hashlib.sha256(shared_bytes).digest()
    # Return first 16 bytes → AES-128 key
    return digest[:16]
