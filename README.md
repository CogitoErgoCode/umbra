# Umbra

Umbra is a command-line utility that implements encryption and decryption upon a file. Passwords are stretched using the scrypt key-derivation function. Umbra implements military grade AES 128-bit block, 256-bit symmetric-key encryption. The mode of operation is cipher block chaining. PKCS#7 Padding is also used along with Hash-Based Message Authentication Code for integrity checking and authentication.

![alt usage](https://github.com/CogitoErgoCode/umbra/blob/master/usage.png)