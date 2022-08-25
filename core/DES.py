from base64 import b64decode, b64encode
from Crypto.Cipher import DES
from SessionKey import generate_random_DES_key
import RSA

# def pad(text):
#     while len(text) % 8 != 0:
#         text+=' '
#     return text

def encrypt(data_file, rsa_public_key):
    session_key = generate_random_DES_key(64)
    data = open(data_file, 'r').read().encode("utf-8")
    # data = pad(data)

    cipher = DES.new(session_key, DES.MODE_OFB)
    encrypted_data = cipher.encrypt(data)
    print(cipher.iv, encrypted_data, "\n\n")
    open("encrypted_data.base64", "wb").write(b64encode(cipher.iv + encrypted_data))

    encrypted_session_key = RSA.encrypt_session_key(session_key, rsa_public_key)
    open("encrypted_key.base64", "wb").write(b64encode(encrypted_session_key))



def decrypt(data_file, enc_key_file, rsa_private_key):
    encrypted_data = b64decode(open(data_file, "rb").read())
    iv = encrypted_data[0:8]
    encrypted_data = encrypted_data[8:]
    print(iv, encrypted_data, "\n\n")

    encrypted_key = b64decode(open(enc_key_file, "rb").read())

    session_key = RSA.decrypt_session_key(encrypted_key, rsa_private_key)

    cipher = DES.new(session_key, DES.MODE_OFB, iv=iv)
    data = cipher.decrypt(encrypted_data)

    open("final_data.txt", "w").write(data.decode("utf-8"))


# with open("criptografado.txt", "wb") as file:
#     file.write(msg)

# with open("criptografado.txt", "rb") as file:
#     iv, x = [file.read(x) for x in (8, -1)]
#     print(iv)
#     print(x)
#     cipher = DES.new(key, DES.MODE_OFB, iv=iv)
#     msg = cipher.decrypt(x)
#     print(msg.decode("utf-8"))

# with open("resultado.txt", "wb") as file:
#     file.write(msg)
