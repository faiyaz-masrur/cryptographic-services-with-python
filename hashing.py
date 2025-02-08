from cryptography.hazmat.primitives import hashes

digest = hashes.Hash(hashes.MD5())
digest.update(b"abc")
q = digest.finalize()

print(q)