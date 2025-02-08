import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, hmac
import base64
global signature

def ase(mode, operation, text, key_size):
    key = os.urandom(key_size)
    iv = os.urandom(16)
    if operation == '1':
        if mode == '1':
            cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
            encryptor = cipher.encryptor()
            padder = PKCS7(algorithms.AES.block_size).padder()
            padded_data = padder.update(text) + padder.finalize()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            encodedciphertext = base64.b64encode(ciphertext)
            print("ciphertext : ", encodedciphertext)
            text = encodedciphertext
        else:
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            padder = PKCS7(algorithms.AES.block_size).padder()
            padded_data = padder.update(text) + padder.finalize()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            encodedciphertext = base64.b64encode(ciphertext)
            print("ciphertext : ", encodedciphertext)
            text = encodedciphertext
        operation = input("Decrypt? (Press 2) : ")
    if operation == '2':
        if mode == '1':
            cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
            decryptor = cipher.decryptor()
            decodedciphertext = base64.b64decode(text)
            padded_data = decryptor.update(decodedciphertext) + decryptor.finalize()
            unpadder = PKCS7(algorithms.AES.block_size).unpadder()
            plaintext = unpadder.update(padded_data) + unpadder.finalize()
            print("plaintext : ", plaintext.decode('utf-8'))
        else:
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decodedciphertext = base64.b64decode(text)
            padded_data = decryptor.update(decodedciphertext) + decryptor.finalize()
            unpadder = PKCS7(algorithms.AES.block_size).unpadder()
            plaintext = unpadder.update(padded_data) + unpadder.finalize()
            print("plaintext : ", plaintext.decode('utf-8'))

def rsaalgo(operation, text, key_size):
    public_exponent = 65537
    private_key = rsa.generate_private_key(public_exponent, key_size)
    public_key = private_key.public_key()
    if operation == '1':
        ciphertext = public_key.encrypt(
            text, padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ))
        print("ciphertext : ", ciphertext)
        text = ciphertext
        operation = input("Decrypt? (Press 2) : ")
    if operation == '2':
        plaintext = private_key.decrypt(
            text, padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            ))
        print("plaintext : ", plaintext.decode('utf-8'))

def hashingalgo(mode, text):
    if mode == '1':
        digest = hashes.Hash(hashes.SHA1())
        digest.update(text)
        hash = digest.finalize()
        print("Hashing : ",hash)
    elif mode == '2':
        digest = hashes.Hash(hashes.SHA256())
        digest.update(text)
        hash = digest.finalize()
        print("Hashing : ", hash)
    elif mode == '3':
        digest = hashes.Hash(hashes.MD5())
        digest.update(text)
        hash = digest.finalize()
        print("Hashing : ", hash)

def sign(operation, text, key_size):
    public_exponent = 65537
    private_key = rsa.generate_private_key(public_exponent, key_size)
    public_key = private_key.public_key()
    if operation == '1':
        signature = private_key.sign(
            text,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256())
        print("Message id signed")
        operation = input("Verify? (Press 2) : ")
        text = input("Message : ").encode()

    if operation == '2':
        verify = public_key.verify(
            signature,
            text,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256())
        print(verify)

def mac(text):
    key = os.urandom(32)
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(text)
    signature = h.finalize()
    print("Mac : ", signature)

def main():
    i = input(" 1.AES \n 2.RSA \n 3.Hashing \n 4.Digital Signature using RSA \n 5.MAC \n Enter number : ")
    if i == '1':
        mode = input("Mode - \n 1.ECB \n 2.CBC \n Enter number : ")
        key_size = int(input("Key_size : "))
        operation = input("Operation - \n 1.Encrypt \n 2.Decrypt \n Enter number : ")
        text = input("Message : ").encode()
        ase(mode, operation, text, key_size)
    elif i == '2':
        key_size = int(input("Key_size : "))
        operation = input("Operation - \n 1.Encrypt \n 2.Decrypt \n Enter number : ")
        text = input("Message : ").encode()
        rsaalgo(operation, text, key_size)
    elif i == '3':
        mode = input("Mode - \n 1.SHA1 \n 2.SHA256 \n 3.MD5 \n Enter number : ")
        text = input("Message : ").encode()
        hashingalgo(mode, text)
    elif i == '4':
        key_size = int(input("Key_size : "))
        operation = input("Operation - \n 1.Generation \n 2.Verification \n Enter number : ")
        text = input("Message : ").encode()
        sign(operation, text, key_size)
    elif i == '5':
        text = input("Message : ").encode()
        mac(text)


if __name__ == "__main__":
    main()