from base64 import b64encode, b64decode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from time import sleep


def encrypt(self, data_file, rsa_public_key):
    file_in = open(data_file, "r")
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


def decrypt(self, data_file, encrypted_key, rsa_private_key):
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
