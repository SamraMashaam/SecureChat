# app/crypto/aes.py

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# PKCS#7 padding
def pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def unpad(padded: bytes) -> bytes:
    pad_len = padded[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid PKCS#7 padding")
    return padded[:-pad_len]

def encrypt_ecb(key: bytes, plaintext: bytes) -> bytes:
    plaintext = pad(plaintext, 16)
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()

def decrypt_ecb(key: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return unpad(plaintext)
