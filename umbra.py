from Crypto.Cipher       import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash         import HMAC, SHA256
from Crypto.Random       import get_random_bytes
from functools           import wraps
import os.path

def file_checks(func):
    @wraps(func)
    def wrapper(self, inF, outF, bufS):
        if not os.path.isfile(inF):
            raise FileNotFoundError("No File!")

        if os.path.exists(outF):
            if os.path.samefile(inF, outF):
                raise ValueError("Same File Path!")

        if bufS % AES.block_size != 0:
            raise ValueError("BufSize Not A Multiple Of AES Block Size!")
        
        return func(self, inF, outF, bufS)
    return wrapper
    
class Rijndael:
    padChr = b'`'

    def __init__(self, key):
        self.__eIV       = get_random_bytes(AES.block_size)
        self.__eKey      = self._to_bytes( key )
        self.__ePassword = self._key_derivation_scrypt( self.__eKey )
        self.__eCipher   = AES.new( self.__ePassword, AES.MODE_CBC, self.__eIV )
        self.__eHMAC     = HMAC.new( self.__ePassword, digestmod=SHA256 )
        
    @staticmethod
    def _to_bytes(value):
        if not isinstance(value, (bytes, bytearray)):
            if not isinstance( value, str ):
                raise TypeError("Bytes or Str Only!")
            value = bytes(value, "utf-8")
        return value

    def _key_derivation_scrypt(self, key, ivSalt=None):
        """
        Key Stretching Implementation
        Produces a 32 Byte / 256-bit Key
        """
        return scrypt(
            password = key,
            salt     = ivSalt or self.__eIV,
            key_len  = AES.key_size[-1],
            N        = 2**AES.block_size,
            r        = AES.block_size,
            p        = 1
        )

    def _encrypt_with_padding(self, plaintext, newCipherObj=None):
        """
        newCipherObj is only to be used when you wish to
        encrypt a new cipher object not supplied by
        the constructor, otherwise just ignore.
        """
        plaintext = self._to_bytes(plaintext)

        if not newCipherObj:
            return self.__eCipher.encrypt(
                pad( plaintext, AES.block_size )
            )
        else:
            return newCipherObj.encrypt(
                pad( plaintext, AES.block_size )
            )

    def _encrypt_without_padding(self, plaintext, newCipherObj=None):
        """
        encrypt_without_padding implements a variation 
        of encrypt that does not utilize padding, for 
        the express purpose of chaining ciphertexts 
        correctly when encrypting files.
        """
        plaintext = self._to_bytes(plaintext)

        if not newCipherObj:
            return self.__eCipher.encrypt( plaintext )
        else:
            return newCipherObj.encrypt( plaintext )

    def _encrypt(self, bytesRead, plaintext, newCipherObj=None):
        # Encrypt bufSize Data (Multiple of AES Blocksize)
        if bytesRead % AES.block_size == 0:
            return self._encrypt_without_padding(plaintext, newCipherObj)
        # Encrypt PKCS#7 "Padded" Plaintext buffer
        else:
            return self._encrypt_with_padding(plaintext, newCipherObj)

    def _decrypt_with_padding(self, ciphertext, newCipherObj=None):
        """
        newCipherObj is only to be used when you wish to
        decrypt a new cipher object not supplied by
        the constructor, otherwise just ignore.
        """
        ciphertext = self._to_bytes(ciphertext)

        if not newCipherObj:
            return unpad( self.__eCipher.decrypt(
                ciphertext
            ), AES.block_size)
        else:
            return unpad( newCipherObj.decrypt(
                ciphertext
            ), AES.block_size)

    def _decrypt_without_padding(self, ciphertext, newCipherObj=None):
        """
        decrypt_raw implements a variation of decrypt
        that does not utilize unpadding, for the express
        purpose of dechaining ciphertexts correctly
        when decrypting files.
        """
        ciphertext = self._to_bytes(ciphertext)

        if not newCipherObj:
            return self.__eCipher.decrypt( ciphertext )
        else:
            return newCipherObj.decrypt( ciphertext )

    def _stamp(self, fileHandle):
        # [64-bytes] Write Stamp
        fill = lambda b: b.center(16, type(self).padChr)
        for stamp in [b"UMBRA", b'1', b"CogitoErgoCode", b"AES"]:
            if len(stamp) > 16:
                raise ValueError("Overflow!")
            fileHandle.write(fill( stamp ))

    def _stamp_unpack(self, fileHandle):
        # [16][16-bytes] Skip program name <0-15>
        fileHandle.seek(16) 

        # [32][16-bytes] Extract version
        version = fileHandle.read(16).replace( type(self).padChr, b'' )
        # Test for correct version
        if int(version) != 1:
            raise ValueError("Incorrect Version!")
        
        # [48][16-bytes] Skip attribution from current position
        fileHandle.seek(16, 1) # dec.seek(48)

        # [64][16-bytes] Extract encryption scheme stored within file
        encryption = fileHandle.read(16).replace( type(self).padChr, b'' ).decode()
        if encryption != "AES":
            raise ValueError("Incorrect Encryption Scheme!")

    def _scheme(self, fileHandle, iv, key):
        """
        This is the decryption scheme to allow an 
        encrypted document to securely carry it's 
        own decryption components
        
        Encrypt-the-mac internal iv & key with 
        external cipher object.

        [eIV] [eCiphertext(iIV+iKey)] [eHMAC(eCiphertext)]
        """
        # [16-bytes] Write External IV
        # enc.write(self.__eCipher.iv)
        fileHandle.write(self.__eIV)

        # [48-bytes] Write External Encrypted (Internal IV + Internal Key)
        # encipheredInternals = self._encrypt_without_padding(iCipher.iv+iKey)
        encipheredInternals = self._encrypt_without_padding(iv+key)
        fileHandle.write(encipheredInternals)

        # [32-bytes] Write External Key HMAC of ^encipheredInternals
        hashedInternals = self.__eHMAC.update(encipheredInternals).digest()
        fileHandle.write(hashedInternals)

    def _scheme_unpack(self, inFilePath, fileHandle):
        # [80][16-bytes] Extract external IV stored within file
        eIV = fileHandle.read(16)

        """
        With the extracted external IV, and the provided key
        we can recreate the external password with the scrypt KDF method
        """
        ePassword = self._key_derivation_scrypt(self.__eKey, eIV)

        # [128][48-bytes] Extract externally Encrypted Internal IV & Key
        encipheredInternals = fileHandle.read(48)
        
        # [160][32-bytes] Extract externally Hashed encipheredInternals
        hashedInternals     = fileHandle.read(32)

        """
        Recalculate & verify external HMAC of encipheredInternals
        """
        eHMAC   = HMAC.new( ePassword, encipheredInternals, digestmod=SHA256 )
        try:
            eHMAC.verify( hashedInternals )
        except ValueError:
            print("Compromised!")

        """
        Decrypt Main Internal IV & Key within encipheredInternals
        """
        eCipher             = AES.new(ePassword, AES.MODE_CBC, eIV)
        decipheredInternals = self._decrypt_without_padding(encipheredInternals, eCipher)
        iIV                 = decipheredInternals[:16] # 16 Byte IV
        iKey                = decipheredInternals[16:] # 32 Byte Key (May also be 24, 16)

        """ 
        Recreate Internal Cipher Object & HMAC
        """
        iCipher = AES.new(iKey, AES.MODE_CBC, iIV)
        iHMAC   = HMAC.new(iKey, digestmod=SHA256)

        return iCipher, iHMAC
    
    @file_checks
    def encrypt_file(self, inFilePath, outFilePath, bufSize=2**16):
        iKey    = get_random_bytes( AES.key_size[-1] )
        iCipher = AES.new ( iKey, AES.MODE_CBC     )
        iHMAC   = HMAC.new( iKey, digestmod=SHA256 )
        # iCipher.iv

        try:
            with open( inFilePath , "rb" ) as dec, \
                 open( outFilePath, "wb" ) as enc:

                # [64-bytes] Write Stamp
                self._stamp(enc)

                # [96-bytes] Write Decryption Scheme Into File
                self._scheme(enc, iCipher.iv, iKey)

                """
                Internal Encryption of Plaintext
                
                [iCiphertext(FILE)] [lastBlockPadded] [iHMAC(iCiphertext)]
                """

                # Iterate over Plaintext Bytes Representation
                # Encrypt Plaintext (Multiple of AES Blocksize)
                while True:
                    buffer    = dec.read(bufSize)
                    bytesRead = len(buffer)

                    # Exit loop on EOF
                    if not bytesRead:
                        break
                    
                    # Upon decryption, if non-zero, unpad
                    lastBlockPadded = bytes([ bytesRead % AES.block_size ])

                    # Retrieve ciphertext
                    cipherText = self._encrypt(bytesRead, buffer, iCipher)

                    # Update Internal Key HMAC (Ciphertext)
                    iHMAC.update(cipherText)

                    # Write Internal Encrypted Data
                    enc.write(cipherText)

                # [ 1-byte ] Write Incongruence
                enc.write(lastBlockPadded)

                # [32-bytes] Write Internal Key HMAC of Ciphertext
                enc.write(iHMAC.digest())

        except:
            raise IOError("File Encryption Failed!")
    
    @file_checks
    def decrypt_file(self, inFilePath, outFilePath, bufSize=2**16):

        try:
            with open( inFilePath , "rb" ) as enc, \
                 open( outFilePath, "wb" ) as dec:

                # [64-bytes] Stamp Handling
                self._stamp_unpack(enc)

                # [160][96-bytes] External Decryption Scheme Handling
                iCipher, iHMAC = self._scheme_unpack(inFilePath, enc)

                # Calculate CipherText offsets
                fileSize    = os.path.getsize(inFilePath)
                cipherBegin = enc.tell()
                cipherEnd   = fileSize - ((1<<5)+1)
                cipherSize  = cipherEnd - cipherBegin

                if cipherSize % AES.block_size != 0:
                    raise ValueError("Ciphertext Corrupt!")
                
                while True:
                    # Up to deficient buffer
                    if enc.tell() < cipherEnd - bufSize:
                        cipherTextBuffer = enc.read(bufSize)

                    # Deficient buffer, read data 16 bytes at a time
                    # Up to last block
                    elif enc.tell() < cipherEnd - AES.block_size:
                        cipherTextBuffer = enc.read(AES.block_size)

                    # last block
                    else:
                        # Extract Last Block, handle empty file on else
                        if enc.tell() != cipherEnd:
                            cipherTextBuffer = enc.read(AES.block_size)
                        else:
                            cipherTextBuffer = b''
                        iHMAC.update(cipherTextBuffer)
                        
                        # Extract Incongruence
                        lastBlockPadded = int.from_bytes( enc.read(1), "big" )

                        # Decrypt Last Block in context to Incongruence
                        if not lastBlockPadded:
                            plainText = self._decrypt_without_padding(cipherTextBuffer, iCipher)
                        else:
                            plainText = self._decrypt_with_padding(cipherTextBuffer, iCipher)

                        # Write Last Block
                        dec.write(plainText)
                        
                        # Extract Internally Hashed CipherText HMAC
                        internalHMAC = enc.read(32)

                        # Verify Internal iHMAC with Extracted Internal HMAC
                        try:
                            iHMAC.verify(internalHMAC) # Raises ValueError if MAC Bad
                        except ValueError:
                            print("Compromised!")

                        break

                    iHMAC.update(cipherTextBuffer)

                    plainText = self._decrypt_without_padding(cipherTextBuffer, iCipher)
                    dec.write(plainText)

        except:
            raise IOError("File Decryption Failed!")
