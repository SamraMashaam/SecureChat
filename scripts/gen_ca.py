# scripts/gen_ca.py
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
import os

def main():
    certs_dir = os.path.join(os.path.dirname(__file__), "..", "certs")
    os.makedirs(certs_dir, exist_ok=True)

    ca_key_path  = os.path.join(certs_dir, "ca.key.pem")
    ca_cert_path = os.path.join(certs_dir, "ca.cert.pem")

    print("[*] Generating Root CA key and certificate...")

    # Generate private key
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    # Build subject/issuer name (self-signed)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat Root CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "SecureChat Root CA"),
    ])

    # Build certificate
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    # Save key (PEM)
    with open(ca_key_path, "wb") as f:
        f.write(
            ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Save certificate (PEM)
    with open(ca_cert_path, "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

    print(f"[+] Root CA created at:\n  {ca_key_path}\n  {ca_cert_path}")

if __name__ == "__main__":
    main()
