from app.crypto import aes

key = b"A" * 16
msg = b"hello world"
ct = aes.encrypt_ecb(key, msg)
pt = aes.decrypt_ecb(key, ct)
print(pt)
