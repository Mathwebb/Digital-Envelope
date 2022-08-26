from crypt import crypt
from hashlib import sha1
from time import sleep
from Crypto.Cipher import ARC4
from Crypto.Hash import SHA256, HMAC
from Crypto.Random import get_random_bytes
from base64 import b64decode, b64encode
from SessionKey import generate_random_RC4_key

def encrypt(data_file, rc4_public_key):
    data = open(data_file, "r").read().encode("utf-8")
    nonce = get_random_bytes(16)
    sessionKey = generate_random_RC4_key()
    tempkey = HMAC.new(sessionKey, nonce, digestmod=SHA256).digest()
    cipher = ARC4.new(tempkey)
    msg = nonce + cipher.encrypt(data)
    open("./results/encrypted/encrypted_data.base64", "wb").write(b64encode(msg))
    open("./results/encrypted/encrypted_key.base64", "wb").write(b64encode(sessionKey))

def decrypt(data_file_output, session_key):
    data = b64decode(open("./results/encrypted/encrypted_data.base64", "r").read())
    salt = data[:16]
    # sessionKeyPlain = crypt(data[16:], sha1(sessionKeyPlain + salt)).digest()

    textPlain = crypt(data[16:], sha1(session_key + salt)).digest()
    open(data_file_output, "wb").write(b64encode(textPlain))
    pass

encrypt('../dados.txt', open("chaves_RSA/public.pem", "rb").read())
decrypt("./results/decrypted/final_data.txt", open("./results/encrypted/encrypted_key.base64", "rb").read())