import json
from app.storage.transcript import Transcript
from app.crypto import pki, sign

def verify(path_log, path_receipt, public_key_path):
    print(f"\nVerifying {path_log} using {path_receipt}")

    # recompute hash from transcript
    tr = Transcript.load_from_file(path_log)
    computed_hash = tr.compute_hash()

    # load receipt
    with open(path_receipt, "r") as f:
        receipt = json.load(f)

    print("Computed transcript hash:", computed_hash)
    print("Receipt transcript hash:", receipt["transcript_sha256"])

    if computed_hash != receipt["transcript_sha256"]:
        print("\n[X] HASH MISMATCH! Transcript was modified.")
        return
    else:
        print("\n[+] HASH MATCH!")

    # verify signature
    cert = pki.load_cert(public_key_path)
    pub = cert.public_key()
    #pub = sign.load_public_key(public_key_path)

    sig = bytes.fromhex(receipt["sig"])
    hash_bytes = bytes.fromhex(computed_hash)
    ok = sign.rsa_verify(pub, hash_bytes, sig)


    if ok:
        print("\n[+] Receipt signature OK — transcript authentic.")
    else:
        print("\n[X] Receipt signature INVALID.")

# Run both verifications manually:
verify("transcripts/client_session_20251115_161829.log", "transcripts/client_session_20251115_161829_receipt.json", "certs/client.cert.pem")
verify("transcripts/server_session_20251115_161829.log", "transcripts/server_session_20251115_161829_receipt.json", "certs/server.cert.pem")
