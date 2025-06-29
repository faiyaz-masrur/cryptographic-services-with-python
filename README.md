# Cryptographic Services 
The cryptographic functions are written with **Python** packages. The main file contains all the functions, and the user can choose the function they have to use. After choosing, they can give input, key to the function for processing, and the function returns output. While choosing functions, one can also choose their modes and operations. The other files contain the functions separately, and the name of the files express their functionalities. The distributed functions in the files do not take any inputs, modes and operations. Users have to pass these parameters manually inside the code.

## ASE
This is a symmetric block cipher that uses the same key to encrypt and decrypt data. The function first takes the mode (the functions implemented only two modes **ECB** and **CBC**), then it needs a key size (Key sizes: 128 bits - 10 rounds, 192 bits - 12 rounds, or 256 bits - 14 rounds) to generate a random key, after that the function takes operation (what to do with the data encrypt it or decrypt it). All these inputs are passed as arguments to the function to generate the desired output.

  ```
  # AES encryption
  cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
  
  ```
