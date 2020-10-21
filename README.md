# umbra

Umbra is a command-line utility that implements encryption and decryption upon a file. Passwords are stretched using the scrypt Key-Derivation Function (KDF). Encryption implements Cipher Block Chaining (CBC), PKCS#7 Padding, and Hash-Based Message Authentication Code (HMAC) for data integrity checking and authentication.