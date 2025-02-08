from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

public_exponent = 65537
key_size = int(input())
private_key = rsa.generate_private_key(
    public_exponent, key_size)

public_key = private_key.public_key()

message = input().encode()
ciphertext = public_key.encrypt(message, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))

print(ciphertext)

message = input().encode()

plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print(plaintext)
