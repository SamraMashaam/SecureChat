# app/storage/transcript.py
import os
import hashlib
import json
from datetime import datetime, timezone
from dotenv import load_dotenv
from app.crypto.sign import rsa_sign, load_private_key
from app.common.utils import sha256_hex

load_dotenv()

TRANSCRIPTS_DIR = os.getenv("TRANSCRIPTS_DIR", "transcripts")
os.makedirs(TRANSCRIPTS_DIR, exist_ok=True)

def get_session_filename(peer_role: str) -> str:
    ts = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
    return os.path.join(TRANSCRIPTS_DIR, f"{peer_role}_session_{ts}.log")

class Transcript:
    def __init__(self, peer_role: str):
        self.file_path = get_session_filename(peer_role)
        self.lines = []  # in-memory log lines (strings)
        self.entries = []

    def append(self, seqno, ts, ct_b64, sig_b64, peer_fingerprint):
        line = f"{seqno}|{ts}|{ct_b64}|{sig_b64}|{peer_fingerprint}"
        self.lines.append(line)

        # Normalize everything to strings
        ct = ct_b64.decode() if isinstance(ct_b64, bytes) else ct_b64
        sig = sig_b64.decode() if isinstance(sig_b64, bytes) else sig_b64

        entry = {
            "seqno": seqno,
            "ts": ts,
            "ct": ct,
            "sig": sig,
            "fingerprint": peer_fingerprint
        }

        self.entries.append(entry)

        with open(self.file_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    
    def compute_hash(self) -> str:
        h = hashlib.sha256()

        for entry in self.entries:
            raw = json.dumps(entry, separators=(",", ":"), sort_keys=True).encode()
            h.update(raw)

        return h.hexdigest()


    def generate_receipt(self, role: str, priv_key_path: str, first_seq: int, last_seq: int) -> dict:
        # Sign transcript hash and return receipt dict
        t_hash = self.compute_hash()
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
    
    @staticmethod
    def load_from_file(path: str) -> "Transcript":
        tr = Transcript("loaded")
        tr.entries = []

        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                # Format: seq|ts|ct|sig|fingerprint
                parts = line.split("|")
                if len(parts) != 5:
                    continue 

                seq, ts, ct, sig, fp = parts

                obj = {
                    "seq": int(seq),
                    "ts": int(ts),
                    "ct": ct,
                    "sig": sig,
                    "fingerprint": fp
                }
                tr.entries.append(obj)

        return tr

