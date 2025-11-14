# app/crypto/dh.py
import secrets, hashlib

# RFC 3526 group14 (2048-bit safe prime)
P = int("""
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
29024E088A67CC74020BBEA63B139B22514A08798E3404DD
EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245
E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF
""".replace("\n", ""), 16)
G = 2

def generate_private_key(bits: int = 256) -> int:
    return secrets.randbits(bits)

def generate_public_key(priv: int) -> int:
    return pow(G, priv, P)

def compute_shared_secret(peer_pub: int, priv: int) -> int:
    return pow(peer_pub, priv, P)

def derive_aes_key(shared_secret: int) -> bytes:
    ks_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7)//8, "big")
    return hashlib.sha256(ks_bytes).digest()[:16]  # AES-128 key
