# app/client.py
import socket, os
from dotenv import load_dotenv

from app.crypto import aes, dh, sign, pki
from app.common.protocol import *
from app.common.utils import now_ms, make_sig_input, b64encode
from app.storage.transcript import Transcript

load_dotenv()

CLIENT_CERT = os.getenv("CLIENT_CERT")
CLIENT_KEY  = os.getenv("CLIENT_KEY")
CA_CERT     = os.getenv("CA_CERT")
SERVER_CERT = os.getenv("SERVER_CERT")

def start_client(host="127.0.0.1", port=9000):
    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    c.connect((host, port))
    transcript = Transcript("client")

    # Send Hello
    hello = HelloMessage(
        client_cert=open(CLIENT_CERT, "r").read(),
        nonce=b64encode(os.urandom(16))
    )
    c.sendall(hello.to_json().encode())

    # Receive server hello
    srv_hello = parse_message(c.recv(8192).decode())

    ok, reason = pki.verify_certificate(
        SERVER_CERT,
        CA_CERT,
        expected_cn="securechat.server"
    )

    if not ok:
        print("[!] Server cert invalid:", reason)
        return

    print("[*] Server cert OK")

    # DH exchange
    a_priv = dh.generate_private_key()
    a_pub = dh.generate_public_key(a_priv)

    c.sendall(DHClient(g=dh.G, p=dh.P, A=a_pub).to_json().encode())

    dh_reply = parse_message(c.recv(8192).decode())
    shared = dh.compute_shared_secret(dh_reply.B, a_priv)
    aes_key = dh.derive_aes_key(shared)

    print("[*] AES key established")

    # Login
    email = input("Email: ")
    pwd = input("Password: ")

    c.sendall(LoginMessage(email=email, pwd=pwd).to_json().encode())

    # Send messages
    seq = 1
    while True:
        pt = input("> ")
        if pt == "exit":
            break

        ts = now_ms()
        ct = aes.encrypt_ecb(aes_key, pt.encode())
        sig_input = make_sig_input(seq, ts, ct)

        priv = sign.load_private_key(CLIENT_KEY)
        sig = sign.rsa_sign(priv, sig_input)

        msg = Msg(
            seqno=seq,
            ts=ts,
            ct=b64encode(ct),
            sig=b64encode(sig)
        )

        c.sendall(msg.to_json().encode())
        transcript.append(seq, ts, msg.ct, msg.sig, "server fingerprint")
        seq += 1

    transcript.generate_receipt("client", CLIENT_KEY, 1, seq-1)
    print("[✓] Receipt generated")

if __name__ == "__main__":
    start_client()
