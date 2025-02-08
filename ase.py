import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
import base64

plaintext = "this is the world where occer."
plaintext = plaintext.encode()
key = os.urandom(16)
iv = os.urandom(16)
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()
padder = PKCS7(algorithms.AES.block_size).padder()
padded_data = padder.update(plaintext) + padder.finalize()
ciphertext = encryptor.update(padded_data) + encryptor.finalize()
encodedciphertext = base64.b64encode(ciphertext)
print(encodedciphertext)

text = "4IBH+PiR8vcrVAkRt8yy9Dw0Cf0y7RJepZgol27NQbw="
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
decryptor = cipher.decryptor()
decodedciphertext = base64.b64decode(text)
padded_data = decryptor.update(decodedciphertext) + decryptor.finalize()
unpadder = PKCS7(algorithms.AES.block_size).unpadder()
plaintext = unpadder.update(padded_data) + unpadder.finalize()
print(plaintext.decode('utf-8'))