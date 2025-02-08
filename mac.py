from cryptography.hazmat.primitives import hashes, hmac
import os
key = os.urandom(32)
h = hmac.HMAC(key, hashes.SHA256())
h.update(b"message to hash")
signature = h.finalize()
print(signature)