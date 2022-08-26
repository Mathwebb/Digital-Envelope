from time import sleep
from Crypto.Cipher import ARC4
from Crypto.Hash import SHA256, HMAC
from Crypto.Random import get_random_bytes
from base64 import b64decode, b64encode
import SessionKey
from Crypto.PublicKey import RSA
import RSA as rsa_local

def encrypt(data_file, rsa_public_key):
    data = open(data_file, "r").read().encode("utf-8")

    nonce = get_random_bytes(16)
    session_key = SessionKey.generate_random_RC4_key()
    encrypted_session_key = rsa_local.encrypt_session_key(session_key, rsa_public_key)

    temp_key = HMAC.new(session_key + nonce, digestmod=SHA256).digest()
    cipher = ARC4.new(temp_key)
    msg = nonce + cipher.encrypt(data)

    open("./core/results/encrypted/encrypted_data.base64", "wb").write(b64encode(msg))
    open("./core/results/encrypted/encrypted_key.base64", "wb").write(b64encode(encrypted_session_key))

def decrypt(data_file, enc_key_file, rsa_private_key):
    encrypted_data_file = b64decode(open(data_file, "rb").read())
    nonce, encrypted_data = [x for x in (encrypted_data_file[0:16], encrypted_data_file[16:])]

    encrypted_key = b64decode(open(enc_key_file, "rb").read())
    session_key = rsa_local.decrypt_session_key(encrypted_key, rsa_private_key)

    temp_key = HMAC.new(session_key + nonce, digestmod=SHA256).digest()
    cipher = ARC4.new(temp_key)
    data = cipher.decrypt(encrypted_data)

    open("./core/results/decrypted/final_data.base64", "w").write(data.decode("utf-8"))

if __name__ == "__main__":
    encrypt("./Exemplos/temp/dados.txt", RSA.import_key(open("./core/chaves_RSA/public.pem", "rb").read()))
    decrypt("./core/results/encrypted/encrypted_data.base64", "./core/results/encrypted/encrypted_key.base64",
            RSA.import_key(open("./core/chaves_RSA/private.pem", "rb").read()))
