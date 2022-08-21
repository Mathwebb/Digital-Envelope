from base64 import b64encode, b64decode
from Crypto.Cipher import AES, PKCS1_OAEP
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

    @property
    def sym_algorithm(self):
        return self._sym_algorithm

    @sym_algorithm.setter
    def sym_algorithm(self, algorithm):
        self._sym_algorithm = algorithm

    @property
    def sym_key_size(self):
        return self._sym_key_size

    @sym_key_size.setter
    def sym_key_size(self, algorithm):
        self._sym_key_size = algorithm

    def cipher(self, file_in, rsa_public_key):
        if self.sym_algorithm.upper() == 'AES':
            file_in = open(file_in, "r")
            data_file_out = open("encrypted_data.bin", "wb")
            key_file_out = open("encrypted_sym_key.bin", "wb")

            session_key = get_random_bytes(16)

            cipher_aes = AES.new(session_key, AES.MODE_EAX)
            ciphertext = cipher_aes.encrypt(file_in.read().encode("utf-8"))
            data_file_out.write(ciphertext)

            cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
            enc_session_key = cipher_rsa.encrypt(session_key)
            key_file_out.write(enc_session_key)
            file_in.close()
            data_file_out.close()
            key_file_out.close()
        elif self.sym_algorithm.upper() == 'DES':
            pass
        elif self.sym_algorithm.upper() == 'RC4':
            pass
        else:
            pass

    def decipher(self, encrypted_data, encrypted_key, rsa_private_key, file_out):
        if self.sym_algorithm.upper() == 'AES':
            file_in = open("encrypted_data.bin", "rb")

            private_key = RSA.import_key(open("private.pem").read())

            ciphertext = file_in.read()

            enc_session_key = open(encrypted_key, "wb").read()

            # Decrypt the session key with the private RSA key
            cipher_rsa = PKCS1_OAEP.new(private_key)
            session_key = cipher_rsa.decrypt(enc_session_key)

            # Decrypt the data with the AES session key
            cipher_aes = AES.new(session_key, AES.MODE_EAX)
            data = cipher_aes.decrypt(ciphertext)
            print(data.decode("utf-8"))
            sleep(4)
        elif self.sym_algorithm.upper() == 'DES':
            pass
        elif self.sym_algorithm.upper() == 'RC4':
            pass
        else:
            pass


if __name__ == '__main__':
    opts = [opt for opt in sys.argv[1:] if opt.startswith("-")]
    args = [arg for arg in sys.argv[1:] if not arg.startswith("-")]

    opts.append("-aes")

    if "-cipher" in opts:
        if "aes" == args[1]:
            Env = Envelope("aes", int(args[2]))
            Env.cipher(args[0], RSA.import_key(open("public.pem", 'rb').read()))

    if "-decipher" in opts:
        if "aes" == args[2]:
            Env = Envelope("aes", 0)
            Env.decipher(args[0], args[1], RSA.import_key(open("private.pem", 'rb').read()), args[3])