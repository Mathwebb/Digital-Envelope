import AES
import DES
import RC4
import SessionKey
import sys
from Crypto.PublicKey import RSA

if __name__ == '__main__':
    opts = [opt for opt in sys.argv[1:] if opt.startswith("-")]
    args = [arg for arg in sys.argv[1:] if not arg.startswith("-")]
    
    # AES.encrypt('dados.txt', RSA.import_key(open("core/chaves_RSA/public.pem", "rb").read()), 128)

    # AES.decrypt("encrypted_data.base64", "encrypted_key.base64", RSA.import_key(open("core/chaves_RSA/private.pem", "rb").read()))

    # if "-cipher" in opts:
    #     if "aes" == args[1]:
    #         AES.encrypt(args[0], RSA.import_key(open("public.pem", 'rb').read()), 128)

    # if "-decipher" in opts:
    #     if "aes" == args[2]:
    #         AES.decrypt(args[0], args[1], RSA.import_key(open("private.pem", 'rb').read()))

    DES.encrypt('dados.txt', RSA.import_key(open("core/chaves_RSA/public.pem", "rb").read()))
    DES.decrypt("encrypted_data.base64", "encrypted_key.base64", RSA.import_key(open("core/chaves_RSA/private.pem", "rb").read()))
