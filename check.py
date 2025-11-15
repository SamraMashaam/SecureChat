import json
from app.storage.transcript import Transcript

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
        print("[X] HASH MISMATCH! Transcript was modified.")
        return

    # verify signature
    from app.crypto import sign
    pub = sign.load_public_key(public_key_path)

    sig = bytes.fromhex(receipt["sig"])
    ok = sign.rsa_verify(pub, computed_hash.encode(), sig)

    if ok:
        print("[✓] Receipt signature OK — transcript authentic.")
    else:
        print("[X] Receipt signature INVALID.")

# Run both verifications manually:
verify("transcripts/client_session_20251115_160245.log", "transcripts/client_session_20251115_160245_receipt.json", "certs/client.cert.pem")
verify("transcripts/server_session_20251115_160245.log", "transcripts/server_session_20251115_160245_receipt.json", "certs/server.cert.pem")
