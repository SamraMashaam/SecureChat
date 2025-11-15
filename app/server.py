# app/server.py
import socket, os, json
from dotenv import load_dotenv

from app.crypto import aes, dh, sign, pki
from app.common.protocol import *
from app.common.utils import now_ms, make_sig_input, b64encode
from app.storage import db
from app.storage.transcript import Transcript

load_dotenv()

SERVER_CERT = os.getenv("SERVER_CERT")  
SERVER_KEY  = os.getenv("SERVER_KEY")   
CA_CERT     = os.getenv("CA_CERT")      

CLIENT_CERT = "certs/client.cert.pem"   

def start_server(host="127.0.0.1", port=9000):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(1)
    print(f"\n[O] Server listening on {host}:{port}")

    conn, addr = s.accept()
    print(f"\n[+] Connection from {addr}")
    transcript = Transcript("server")

    # Receive hello
    hello_raw = conn.recv(8192).decode()
    hello = parse_message(hello_raw)
    print("\n[*] Received Hello")

    # Verify client certificate
    ok, reason = pki.verify_certificate(
        CLIENT_CERT,
        CA_CERT,
        expected_cn="securechat.client"
    )

    if not ok:
        print("\n[!] Client cert invalid:", reason)
        conn.close()
        return

    # Send server hello (with newline framing)
    server_hello = ServerHello(
        server_cert=open(SERVER_CERT, "r").read(),
        nonce=b64encode(os.urandom(16))
    )
    conn.sendall(server_hello.to_json().encode() + b"\n")

    # Receive DH
    dh_raw = conn.recv(8192).decode()
    dh_msg = parse_message(dh_raw)

    if dh_msg.type != "dh_client":
        print("\n[!] Expected dh_client message")
        conn.close()
        return

    print("\n[*] Received DH parameters from client")

    # Convert received numbers
    client_p = int(dh_msg.p)
    client_g = int(dh_msg.g)
    client_A = int(dh_msg.A)

    # Generate server exponent (b)
    server_b = dh.gen_private()

    # Compute B = g^b mod p
    server_B = pow(client_g, server_b, client_p)

    # Compute shared secret Ks = A^b mod p
    shared = pow(client_A, server_b, client_p)

    # Derive AES key from shared secret
    aes_key = dh.derive_key(shared)
    print("\n[DEBUG] Server AES key:", aes_key.hex())
    print("\n[+] DH complete — AES session key established")

    # Send DHServer message back (with newline)
    resp = DHServer(B=str(server_B))
    conn.sendall(resp.to_json().encode() + b"\n")

    # Receive login (ensure newline framing on client side too)
    login_raw = conn.recv(4096).decode()
    login = parse_message(login_raw)

    if not db.verify_login(login.email, login.pwd):
        print("[!] Login failed.")
        conn.sendall(ErrorMessage(reason="Invalid login").to_json().encode() + b"\n")
        conn.close()
        return

    print("\n[+] Login OK")
    server_priv = sign.load_private_key(SERVER_KEY)
    server_seq = 1

    # Keep track of client seqs to compute ranges for receipts
    client_first_seq = None
    last_client_seq = 0

    # Receive messages
    last_seq = 0

    while True:
        try:
            raw = conn.recv(8192)
            if not raw:
                # client closed gracefully
                print("\n[*] Client closed connection (EOF)")
                break

        except ConnectionResetError:
            # client crashed or exited early
            print("\n[*] Client disconnected (connection reset)")
            break

        except Exception as e:
            print("\n[!] Socket error:", e)
            break

        try:
            msg = parse_message(raw.decode())
        except Exception:
            print("\n[!] Invalid JSON received")
            continue

        if msg.type != "msg":
            continue

        # Replay protection
        if msg.seqno <= last_seq:
            print("\n[!] Replay/out-of-order message")
            continue
        last_seq = msg.seqno

        # Set client_first_seq on first client message
        if client_first_seq is None:
            client_first_seq = msg.seqno
        last_client_seq = msg.seqno

        # Extract client pubkey
        client_cert = pki.load_cert(CLIENT_CERT)
        client_pub = client_cert.public_key()

        # Rebuild signature input
        ct_bytes = msg.ct_bytes()
        sig_input = make_sig_input(msg.seqno, msg.ts, ct_bytes)

        # Verify signature
        if not sign.rsa_verify(client_pub, sig_input, msg.sig_bytes()):
            print("\n[!] Signature invalid")
            continue

        # Decrypt
        try:
            pt = aes.decrypt_ecb(aes_key, ct_bytes).decode()
        except Exception:
            print("\n[!] AES decrypt failed")
            continue

        # Log client message FIRST (chronological order)
        fingerprint = make_sig_input(msg.seqno, msg.ts, msg.ct_bytes()).hex()
        transcript.append(msg.seqno, msg.ts, msg.ct, msg.sig, fingerprint)

        print(f"[client:{msg.seqno}] {pt}")

        reply_pt = f"Server ack: {pt}".encode()
        reply_ct = aes.encrypt_ecb(aes_key, reply_pt)
        reply_ts = now_ms()

        reply_sig_input = make_sig_input(server_seq, reply_ts, reply_ct)
        reply_sig = sign.rsa_sign(server_priv, reply_sig_input)

        reply_msg = Msg(
            seqno=server_seq,
            ts=reply_ts,
            ct=b64encode(reply_ct),
            sig=b64encode(reply_sig)
        )

        # send server reply with newline framing
        conn.sendall(reply_msg.to_json().encode() + b"\n")
        reply_fingerprint = make_sig_input(server_seq, reply_ts, reply_ct).hex()
        transcript.append(server_seq, reply_ts, reply_msg.ct, reply_msg.sig, reply_fingerprint)

        server_seq += 1
        if (pt == "exit"):
            break

    # End receipt
    first_seq = client_first_seq if client_first_seq is not None else 0
    last_seq = max(last_client_seq, server_seq - 1)

    # generate receipt covering the transcript we logged
    receipt = transcript.generate_receipt("server", SERVER_KEY, first_seq, last_seq)
    print("\n[=] Receipt generated:", receipt["transcript_sha256"])

if __name__ == "__main__":
    start_server()
