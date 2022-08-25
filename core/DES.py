from base64 import b64decode, b64encode
from Crypto.Cipher import DES
from SessionKey import generate_random_DES_key
import RSA

def encrypt(data_file, rsa_public_key):
    session_key = generate_random_DES_key(64)
    data = open(data_file, 'r').read().encode("utf-8")

    cipher = DES.new(session_key, DES.MODE_OFB)
    encrypted_data = cipher.encrypt(data)
    open("./core/results/encrypted/encrypted_data.base64", "wb").write(b64encode(cipher.iv + encrypted_data))

    encrypted_session_key = RSA.encrypt_session_key(session_key, rsa_public_key)
    open("./core/results/encrypted/encrypted_key.base64", "wb").write(b64encode(encrypted_session_key))



def decrypt(data_file, enc_key_file, rsa_private_key):
    encrypted_data = b64decode(open(f"./core/results/encrypted/{data_file}", "rb").read())
    iv = encrypted_data[0:8]
    encrypted_data = encrypted_data[8:]

    encrypted_key = b64decode(open(f"./core/results/encrypted/{enc_key_file}", "rb").read())

    session_key = RSA.decrypt_session_key(encrypted_key, rsa_private_key)

    cipher = DES.new(session_key, DES.MODE_OFB, iv=iv)
    data = cipher.decrypt(encrypted_data)

    open("./core/results/decrypted/final_data.txt", "w").write(data.decode("utf-8"))
