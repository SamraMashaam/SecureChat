# app/crypto/sign.py
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa

def load_private_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def rsa_sign(priv_key, data: bytes) -> bytes:
    return priv_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

def rsa_verify(pub_key, data: bytes, signature: bytes) -> bool:
    try:
        pub_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False
