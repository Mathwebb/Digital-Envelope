from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from base64 import b64encode

data = "I met aliens in UFO. Here is the map.".encode("utf-8")
file_out = open("encrypted_data.bin", "wb+")

recipient_key = RSA.import_key(open("receiver.pem").read())
session_key = get_random_bytes(16)

# Encrypt the session key with the public RSA key
cipher_rsa = PKCS1_OAEP.new(recipient_key)
enc_session_key = cipher_rsa.encrypt(session_key)

# Encrypt the data with the AES session key
cipher_aes = AES.new(session_key, AES.MODE_EAX)
ciphertext, tag = cipher_aes.encrypt_and_digest(data)
[file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext)]
with open("encrypted_data.base64", "wb") as file:
    file_out.seek(0)
    file.write(b64encode(file_out.read()))
file_out.close()

with open("encrypted_data.bin", "rb") as file:
    b64_encode = b64encode(file.read())

with open("encrypted_data1.base64", "wb") as file:
    file.write(b64_encode)
