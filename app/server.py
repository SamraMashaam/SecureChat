# app/server.py
import socket, os, json
from dotenv import load_dotenv

from app.crypto import aes, dh, sign, pki
from app.common.protocol import *
from app.common.utils import now_ms, make_sig_input, b64encode
from app.storage import db
from app.storage.transcript import Transcript

load_dotenv()

SERVER_CERT = os.getenv("SERVER_CERT")  # certs/server.cert.pem
SERVER_KEY  = os.getenv("SERVER_KEY")   # certs/server.key.pem
CA_CERT     = os.getenv("CA_CERT")      # certs/ca.cert.pem

CLIENT_CERT = "certs/client.cert.pem"   # path for verification

def start_server(host="127.0.0.1", port=9000):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(1)
    print(f"[O] Server listening on {host}:{port}")

    conn, addr = s.accept()
    print(f"[+] Connection from {addr}")
    transcript = Transcript("server")

    # Receive hello
    hello_raw = conn.recv(8192).decode()
    hello = parse_message(hello_raw)
    print("[*] Received Hello")

    # Verify client certificate
    ok, reason = pki.verify_certificate(
        CLIENT_CERT,
        CA_CERT,
        expected_cn="securechat.client"
    )

    if not ok:
        print("[!] Client cert invalid:", reason)
        conn.close()
        return

    # Send server hello
    server_hello = ServerHello(
        server_cert=open(SERVER_CERT, "r").read(),
        nonce=b64encode(os.urandom(16))
    )
    conn.sendall(server_hello.to_json().encode())

    # Receive DH
    dh_raw = conn.recv(8192).decode()
    dh_msg = parse_message(dh_raw)

    B_priv = dh.generate_private_key()
    B_pub = dh.generate_public_key(B_priv)
    shared = dh.compute_shared_secret(dh_msg.A, B_priv)
    aes_key = dh.derive_aes_key(shared)

    conn.sendall(DHServer(B=B_pub).to_json().encode())
    print("[*] Shared AES key established")

    # Receive login
    login_raw = conn.recv(4096).decode()
    login = parse_message(login_raw)

    if not db.verify_login(login.email, login.pwd):
        print("[!] Login failed.")
        conn.sendall(ErrorMessage(reason="Invalid login").to_json().encode())
        conn.close()
        return

    print("[+] Login OK")

    # Receive messages
    while True:
        raw = conn.recv(8192)
        if not raw:
            break
        msg = parse_message(raw.decode())

        if msg.type != "msg":
            continue

        # Extract client public key from client certificate
        client_cert = pki.load_cert(CLIENT_CERT)
        client_pub = client_cert.public_key()

        sig_input = make_sig_input(msg.seqno, msg.ts, msg.ct_bytes())

        if not sign.rsa_verify(client_pub, sig_input, msg.sig_bytes()):
            print("[!] Signature invalid")
            continue

        pt = aes.decrypt_ecb(aes_key, msg.ct_bytes()).decode()
        print(f"[client:{msg.seqno}] {pt}")

        transcript.append(msg.seqno, msg.ts, msg.ct, msg.sig, "client fingerprint")

    # End receipt
    receipt = transcript.generate_receipt("server", SERVER_KEY, 1, 9999)
    print("[✓] Receipt generated")

if __name__ == "__main__":
    start_server()
