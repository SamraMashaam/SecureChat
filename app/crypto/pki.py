# app/crypto/pki.py
import os
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from datetime import datetime
from dotenv import load_dotenv
from cryptography.hazmat.primitives.asymmetric import padding



load_dotenv()

def load_cert(path: str):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())

def verify_certificate(cert_path: str, ca_cert_path: str, expected_cn: str):
    try:
        cert = load_cert(cert_path)
        ca_cert = load_cert(ca_cert_path)

        # 1) Verify signature
        ca_pub = ca_cert.public_key()
        ca_pub.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )


        # 2) Check validity period
        now = datetime.utcnow()
        if now < cert.not_valid_before or now > cert.not_valid_after:
            return False, "Certificate expired or not yet valid."

        # 3) Check CN matches expected
        cn_attr = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if not cn_attr:
            return False, "Certificate missing CN"
        cn = cn_attr[0].value

        if cn != expected_cn:
            return False, f"CN mismatch: expected {expected_cn}, got {cn}"

        return True, "VALID"

    except Exception as e:
        return False, f"BAD CERT: {e}"
