# app/client.py
import socket, os
import threading
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

def send_encrypted(conn, plaintext: str, aes_key: bytes, rsa_key, seqno: int):
    from app.crypto import aes, sign
    from app.common.utils import now_ms, make_sig_input, b64encode

    pt_bytes = plaintext.encode()
    ct_bytes = aes.encrypt_ecb(aes_key, pt_bytes)
    ts = now_ms()

    sig_input = make_sig_input(seqno, ts, ct_bytes)
    sig_bytes = sign.rsa_sign(rsa_key, sig_input)

    msg = Msg(
        seqno=seqno,
        ts=ts,
        ct=b64encode(ct_bytes),
        sig=b64encode(sig_bytes)
    )

    conn.sendall(msg.to_json().encode() + b"\n")

def listen_for_server(conn, aes_key, server_pub, transcript):
    while True:
        try:
            raw = conn.recv(8192)
            if not raw:
                break

            msg = parse_message(raw.decode())

            if msg.type != "msg":
                continue

            # Verify signature
            sig_input = make_sig_input(msg.seqno, msg.ts, msg.ct_bytes())
            if not sign.rsa_verify(server_pub, sig_input, msg.sig_bytes()):
                print("\n[!] Invalid server signature")
                continue

            # Decrypt AES ciphertext
            pt = aes.decrypt_ecb(aes_key, msg.ct_bytes()).decode()

            print(f"\n[server:{msg.seqno}] {pt}")

            # inside the receive loop after verifying signature
            fingerprint = make_sig_input(msg.seqno, msg.ts, msg.ct_bytes()).hex()
            transcript.append(msg.seqno, msg.ts, msg.ct, msg.sig, fingerprint)


        except Exception as e:
            print("\n[!] Listener error:", e)
            break


def start_client(host="127.0.0.1", port=9000):
    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    c.connect((host, port))
    transcript = Transcript("client")

    # Send Hello
    hello = HelloMessage(
        client_cert=open(CLIENT_CERT, "r").read(),
        nonce=b64encode(os.urandom(16))
    )
    c.sendall(hello.to_json().encode() + b"\n")

    # Receive server hello
    srv_hello = parse_message(c.recv(8192).decode())
    p = dh.P
    g = dh.G

    # Generate client exponent (a)
    client_a = dh.gen_private()

    # Compute A = g^a mod p
    A = pow(g, client_a, p)

    # Send DHClient message
    dh_client = DHClient(
        p=str(p),
        g=str(g),
        A=str(A)
    )
    c.sendall(dh_client.to_json().encode() + b"\n")
    print("\n[*] Sent DH parameters to server")

    # Receive DHServer reply
    dh_srv_raw = c.recv(8192).decode()
    dh_srv = parse_message(dh_srv_raw)

    if dh_srv.type != "dh_server":
        print("\n[!] Expected dh_server message")
        c.close()
        return

    server_B = int(dh_srv.B)

    # Compute shared secret
    shared = pow(server_B, client_a, p)

    # Derive AES session key
    aes_key = dh.derive_key(shared)
    print("\n[DEBUG] CLIENT AES key:", aes_key.hex())
    print("\n[+] DH complete — AES session key established")

    ok, reason = pki.verify_certificate(
        SERVER_CERT,
        CA_CERT,
        expected_cn="securechat.server"
    )
    server_cert = pki.load_cert(SERVER_CERT)
    server_pub = server_cert.public_key()

    if not ok:
        print("\n[!] Server cert invalid:", reason)
        return

    print("\n[*] Server cert OK")
    # Start listener thread
    listener = threading.Thread(
        target=listen_for_server,
        args=(c, aes_key, server_pub, transcript),
        daemon=True
    )
    listener.start()


    # Login
    email = input("Email: ")
    pwd = input("Password: ")

    c.sendall(LoginMessage(email=email, pwd=pwd).to_json().encode() + b"\n")

    # Send messages
    print("\n[*] Secure chat started. Type messages and press Enter.\n Type 'exit' to end")
    seq = 1

    from cryptography.hazmat.primitives import serialization
    client_priv = serialization.load_pem_private_key(
        open(CLIENT_KEY, "rb").read(),
        password=None
    )

    while True:
        pt = input("> ")
        if pt.strip().lower() == "exit":
            break

        # Send encrypted message using helper
        send_encrypted(c, pt, aes_key, client_priv, seq)

        # Log transcript entry
        ts = now_ms()
        ct_bytes = aes.encrypt_ecb(aes_key, pt.encode())
        sig_input = make_sig_input(seq, ts, ct_bytes)
        sig = sign.rsa_sign(client_priv, sig_input)

        fingerprint = make_sig_input(seq, ts, ct_bytes).hex()
        transcript.append(seq, ts, ct_bytes, sig, fingerprint)


        seq += 1

    # End session
    transcript.generate_receipt("client", CLIENT_KEY, 1, seq - 1)
    print("\n[=] Receipt generated")


if __name__ == "__main__":
    start_client()
