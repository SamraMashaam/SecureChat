from app.storage.transcript import Transcript
t = Transcript("client")
t.append(1, 1762922222222, "Y2lwaGVy", "c2ln", "fingerprint123")
print("Hash:", t.compute_transcript_hash())
# generate a dummy receipt (replace with your actual key path)
# t.generate_receipt("client", "certs/client.key.pem", 1, 1)
