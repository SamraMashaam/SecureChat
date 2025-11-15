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
    """
    Transcript maintains:
     - self.lines: raw pipe-separated lines (for human readability)
     - self.entries: canonical list of dicts used for deterministic hashing
    Canonical entry format (dict):
      {
        "seq": int,
        "ts": int,
        "ct": str,          # base64 ciphertext
        "sig": str,         # base64 signature
        "fingerprint": str  # hex of SHA256(seq||ts||ct_bytes)
      }
    """
    def __init__(self, peer_role: str):
        self.file_path = get_session_filename(peer_role)
        self.lines = []      # raw pipe-separated lines
        self.entries = []    # canonical parsed entries used for hashing

    def append(self, seqno, ts, ct_b64, sig_b64, peer_fingerprint):
        """
        Append a new entry to the transcript.
        ct_b64 and sig_b64 must be base64-encoded strings (or bytes)
        """
        # Normalize ct and sig to strings
        ct = ct_b64.decode() if isinstance(ct_b64, (bytes, bytearray)) else ct_b64
        sig = sig_b64.decode() if isinstance(sig_b64, (bytes, bytearray)) else sig_b64

        # Build raw line for logfile (pipe-separated for readability)
        line = f"{seqno}|{ts}|{ct}|{sig}|{peer_fingerprint}"
        self.lines.append(line)

        # Build canonical entry (note: key name is "seq")
        entry = {
            "seq": int(seqno),
            "ts": int(ts),
            "ct": str(ct),
            "sig": str(sig),
            "fingerprint": str(peer_fingerprint)
        }
        self.entries.append(entry)

        # Persist raw line to file (append-only)
        with open(self.file_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")

    def compute_hash(self) -> str:
        """
        Deterministically compute SHA-256(hex) over canonical JSON entries.
        Uses json.dumps(..., sort_keys=True, separators=(',',':')) to ensure
        identical canonical representation on both sides.
        """
        h = hashlib.sha256()
        for entry in self.entries:
            # canonical JSON bytes
            raw = json.dumps(entry, separators=(",", ":"), sort_keys=True).encode()
            h.update(raw)
        return h.hexdigest()

    def generate_receipt(self, role: str, priv_key_path: str, first_seq: int, last_seq: int) -> dict:
        """
        Sign the transcript hash and write a receipt JSON next to the transcript file.
        """
        t_hash = self.compute_hash()
        priv_key = load_private_key(priv_key_path)
        sig = rsa_sign(priv_key, bytes.fromhex(t_hash))
        receipt = {
            "type": "receipt",
            "peer": role,
            "first_seq": first_seq,
            "last_seq": last_seq,
            "transcript_sha256": t_hash,
            "sig": sig.hex(),
        }
        receipt_path = self.file_path.replace(".log", "_receipt.json")
        with open(receipt_path, "w", encoding="utf-8") as f:
            json.dump(receipt, f, indent=2)
        return receipt

    @staticmethod
    def load_from_file(path: str) -> "Transcript":
        """
        Load a transcript file (pipe-delimited lines) and reconstruct canonical entries.
        Returns a Transcript instance whose .entries can be hashed with compute_hash().
        """
        tr = Transcript("loaded")
        tr.entries = []

        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                parts = line.split("|")
                if len(parts) != 5:
                    # skip malformed lines
                    continue

                seq, ts, ct, sig, fp = parts

                # normalize types to match runtime append()
                obj = {
                    "seq": int(seq),
                    "ts": int(ts),
                    "ct": ct,
                    "sig": sig,
                    "fingerprint": fp
                }
                tr.entries.append(obj)

        return tr
