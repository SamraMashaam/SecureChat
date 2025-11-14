# scripts/gen_cert.py
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
import os, argparse

def issue_cert(entity: str, cn: str):
    certs_dir = os.path.join(os.path.dirname(__file__), "..", "certs")
    os.makedirs(certs_dir, exist_ok=True)

    ca_key_path  = os.path.join(certs_dir, "ca.key.pem")
    ca_cert_path = os.path.join(certs_dir, "ca.cert.pem")

    if not (os.path.exists(ca_key_path) and os.path.exists(ca_cert_path)):
        raise FileNotFoundError("Root CA key/cert not found – run gen_ca.py first.")

    # Load CA key and cert
    from cryptography.hazmat.primitives import serialization
    from cryptography import x509

    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    # Generate entity key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat User"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])

    # Build certificate signed by CA
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=730))  # 2 years
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    # Write files
    key_path  = os.path.join(certs_dir, f"{entity}.key.pem")
    cert_path = os.path.join(certs_dir, f"{entity}.cert.pem")

    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"[+] Issued {entity} certificate for CN={cn}\n  {key_path}\n  {cert_path}")

def main():
    parser = argparse.ArgumentParser(description="Issue server/client certificate signed by Root CA.")
    parser.add_argument("--type", choices=["client", "server"], required=True)
    parser.add_argument("--cn", default=None, help="Common Name (CN) for certificate")
    args = parser.parse_args()

    cn = args.cn or f"{args.type}.securechat.local"
    issue_cert(args.type, cn)

if __name__ == "__main__":
    main()
