from time import sleep
from Crypto.Cipher import ARC4
from Crypto.Hash import SHA256, HMAC
from Crypto.Random import get_random_bytes
from base64 import b64decode, b64encode

def encrypt(data_file, rc4_public_key):
    data = open(data_file, "r").read().encode("utf-8")
    nonce = get_random_bytes(16)
    tempkey = HMAC.new(rc4_public_key, nonce, digestmod=SHA256).digest()
    cipher = ARC4.new(tempkey)
    msg = nonce + cipher.encrypt(data)
    open("encrypted_data.base64", "wb").write(b64encode(msg))

def decrypt(data_file, enc_key_file, rsa_private_key):
    pass
