import os, sys, argparse

class Args:
    BANNER = """
███    █▄    ▄▄▄▄███▄▄▄▄   ▀█████████▄     ▄████████    ▄████████ 
███    ███ ▄██▀▀▀███▀▀▀██▄   ███    ███   ███    ███   ███    ███ 
███    ███ ███   ███   ███   ███    ███   ███    ███   ███    ███ 
███    ███ ███   ███   ███  ▄███▄▄▄██▀   ▄███▄▄▄▄██▀   ███    ███ 
███    ███ ███   ███   ███ ▀▀███▀▀▀██▄  ▀▀███▀▀▀▀▀   ▀███████████ 
███    ███ ███   ███   ███   ███    ██▄ ▀███████████   ███    ███ 
███    ███ ███   ███   ███   ███    ███   ███    ███   ███    ███ 
████████▀   ▀█   ███   █▀  ▄█████████▀    ███    ███   ███    █▀  
                                          ███    ███              
"""

    intro = f"""{sys.platform} pid: {os.getppid()}\n{BANNER}
Umbra: File Encryption Utility v1.0
Blog : cogitoergocode.github.io/rijndael/
Usage: umbra.py [Option(s)] {{Argument specification}}

Options:
    -h,  --help     You're here ;)
    -v,  --version  Show Version Information

Cryptography Options:
    -e,  --encrypt <password> <path>
    -d,  --decrypt <password> <path>

Example:
  ./umbra.py --encrypt p@55w0rd ..\\path
  ./umbra.py --encrypt p@55w0rd ~\\Desktop\\path
  ./umbra.py --encrypt p@55w0rd %userprofile%\\Desktop\\path"""

    def __init__(self):
        parser = argparse.ArgumentParser(
            add_help = False, 
            prog     = "Umbra"
        )
        
        parser.add_argument(
            "-h", "--help", 
            action = "store_true", 
            help   = "You are Here ..."
        )

        parser.add_argument(
            "-v", "--version", 
            action  = "version", 
            version = "%(prog)s 1.0",
            help    = "Show Version Information"
        )

        parser.add_argument(
            "-e", "--encrypt",
            metavar = ("<Password>", "<filePath>"),
            nargs   = 2,
            type    = str,
            help    = "encrypt file"
        )

        parser.add_argument(
            "-d", "--decrypt",
            metavar = ("<Password>", "<filePath>"),
            nargs   = 2,
            type    = str,
            help    = "decrypt file"
        )

        self.args = parser.parse_args()

    @property
    def dct_args(self):
        return vars(self.args)

    def process(self):
        if self.dct_args.get("help") or not any(self.dct_args.values()):
            print( f"{type(self).intro}" )
            sys.exit()
