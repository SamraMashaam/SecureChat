# app/storage/transcript.py
import os
import hashlib
import json
from datetime import datetime
from dotenv import load_dotenv
from app.crypto.sign import rsa_sign, load_private_key
from app.common.utils import sha256_hex

load_dotenv()

TRANSCRIPTS_DIR = os.getenv("TRANSCRIPTS_DIR", "transcripts")
os.makedirs(TRANSCRIPTS_DIR, exist_ok=True)

def get_session_filename(peer_role: str) -> str:
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    return os.path.join(TRANSCRIPTS_DIR, f"{peer_role}_session_{ts}.log")

class Transcript:
    def __init__(self, peer_role: str):
        self.file_path = get_session_filename(peer_role)
        self.lines = []  # in-memory log lines (strings)

    def append(self, seqno: int, ts: int, ct_b64: str, sig_b64: str, peer_fingerprint: str):
        line = f"{seqno}|{ts}|{ct_b64}|{sig_b64}|{peer_fingerprint}"
        self.lines.append(line)
        with open(self.file_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")

    def compute_transcript_hash(self) -> str:
        # Compute SHA-256 hex digest of concatenated transcript lines
        joined = "\n".join(self.lines).encode("utf-8")
        return sha256_hex(joined)

    def generate_receipt(self, role: str, priv_key_path: str, first_seq: int, last_seq: int) -> dict:
        # Sign transcript hash and return receipt dict
        t_hash = self.compute_transcript_hash()
        priv_key = load_private_key(priv_key_path)
        sig = rsa_sign(priv_key, bytes.fromhex(t_hash))
        receipt = {
            "type": "receipt",
            "peer": role,
            "first_seq": first_seq,
            "last_seq": last_seq,
            "transcript_sha256": t_hash,
            "sig": sig.hex(),  # store signature hex for readability
        }
        receipt_path = self.file_path.replace(".log", "_receipt.json")
        with open(receipt_path, "w", encoding="utf-8") as f:
            json.dump(receipt, f, indent=2)
        return receipt
