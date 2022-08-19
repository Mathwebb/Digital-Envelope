from base64 import b64encode, b64decode
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import sys
from time import sleep


def generate_rsa_keys(key_size: int) -> dict:
    key = RSA.generate(key_size)
    public_key = key.public_key().export_key()
    private_key = key.export_key()
    return {"public_key": public_key, "private_key": private_key}


class Envelope:
    def __init__(self, sym_algorithm: str, sym_key_size: int):
        print("Opa, vamo que vamo")
        self.sym_algorithm = sym_algorithm
        self.sym_key_size = sym_key_size

    def cipher(self, data, RSA_public_key):
        if (self.sym_algorithm.upper() == 'AES'):
            print("Usando aes")
            sleep(3)
            pass
        elif (self.sym_algorithm.upper() == 'DES'):
            pass
        elif (self.sym_algorithm.upper() == 'RC4'):
            pass
        else:
            pass


    def decipher(self, encrypted_data, encrypted_key, RSA_private_key):
        pass

if __name__ == '__main__':
    opts = [opt for opt in sys.argv[1:] if opt.startswith("-")]
    args = [arg for arg in sys.argv[1:] if not arg.startswith("-")]

    if "-aes" in opts:
        Env = Envelope("aes", args[0])
