# umbra

Umbra is a command-line utility that implements encryption and decryption upon a file. Passwords are stretched using the scrypt Key-Derivation Function (KDF). Umbra implements military grade AES 128-bit (16-byte) block, 256-bit (32-byte) symmetric-key encryption. The mode of operation is Cipher Block Chaining (CBC). PKCS#7 Padding is also used along with Hash-Based Message Authentication Code (HMAC) for integrity checking and authentication.

![alt usage](https://github.com/CogitoErgoCode/umbra/blob/master/usage.png)