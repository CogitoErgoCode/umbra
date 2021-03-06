from control.args import Args
from ciphers.aes  import Rijndael
import os.path, re

bufferSize = 2**16

expander = lambda path: os.path.abspath( 
    os.path.expanduser( 
        os.path.expandvars( path ) 
    ) 
)

def main():
    args = Args()
    args.process()

    if args.dct_args.get('encrypt'):
        password, path = args.dct_args.get('encrypt')
        path = expander(path)

        if password and path:
            cipherObj = Rijndael(password)
            try:
                cipherObj.encrypt_file(path, path+".um", bufferSize)
            except Exception as error:
                print("[ ! ] Encryption Failed\n" + " "*6 + f"{error}...")
            else:
                print("[ * ] Encryption Succeeded.")

    if args.dct_args.get('decrypt'):
        password, path = args.dct_args.get('decrypt')
        path = expander(path)
        ext  = re.search(r"(\.\w+)\.um$", path, re.I).group(1)

        if password and path:
            cipherObj = Rijndael(password)
            try:
                cipherObj.decrypt_file(path, path+ext, bufferSize)
            except Exception as error:
                print("[ ! ] Decryption Failed\n" + " "*6 + f"{error}...")
            else:
                print("[ * ] Decryption Succeeded.")

if __name__ == "__main__":
    main()