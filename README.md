# Cryptographic Services 
The cryptographic functions are written with **Python** packages. The main file contains all the functions, and the user can choose the function they have to use. After choosing, they can give input, key to the function for processing, and the function returns output. While choosing functions, one can also choose their modes and operations. The other files contain the functions separately, and the name of the files express their functionalities. The distributed functions in the files do not take any inputs, modes and operations. Users have to pass these parameters manually inside the code.

## AES
This is a symmetric block cipher that uses the same key to encrypt and decrypt data. The function first takes the mode (the functions implemented only two modes **ECB** and **CBC**), then it needs a key size (Key sizes: 128 bits - 10 rounds, 192 bits - 12 rounds, or 256 bits - 14 rounds) to generate a random key, after that the function takes operation (what to do with the data encrypt it or decrypt it). All these inputs are passed as arguments to the function to generate the desired output.

#### Encryption

  ```
  # AES encryption
  # Cipher, algorithms, and modes: Used to create AES cipher.
  cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
  encryptor = cipher.encryptor()

  # Padding the plaintext to be a multiple of 16 bytes
  padder = padding.PKCS7(128).padder()
  padded_data = padder.update(plaintext.encode()) + padder.finalize()

  # Returns ciphertext
  ciphertext = encryptor.update(padded_data) + encryptor.finalize()
  ```

#### Decryption

  ```
  # AES decryption
  # Create the AES cipher with the same key and IV used during encryption
  cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
  decryptor = cipher.decryptor()

  padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()

  #Decrypt the ciphertext back into padded plaintext
  unpadder = padding.PKCS7(128).unpadder()
  plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
  ```

## RSA
This is an asymmetric encryption algorithm. Unlike AES (which is symmetric), RSA uses two different keys: 1. A public key to encrypt data, 2. A private key to decrypt data. For encrypting and decrypting, the function takes input size (typically 2048 or 4096 bits) to generate private and public keys, then it takes encryption and decryption commands, and lastly it inputs text to perform the operation. 

```
# Generate keys
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()
```

#### Encryption

```
# RSA Encrypt
ciphertext = public_key.encrypt(
    message,
    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)
```

#### Decryption

```
# Decrypt
plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)
```

## Hashing Function

