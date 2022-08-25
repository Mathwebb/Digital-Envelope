from base64 import b64decode, b64encode
from Crypto.Cipher import AES
import RSA, SessionKey
encrypted_files_default = "./core/results/encrypted/"
decrypted_files_default = "./core/results/decrypted/"


def encrypt(data_file, rsa_public_key, sym_key_size):
    data = open(data_file, "r").read().encode("utf-8")

    # Encrypt the message with the session key
    session_key = SessionKey.generate_random_AES_key(sym_key_size)
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    encrypted_data = cipher_aes.encrypt(data)
    enc_session_key = RSA.encrypt_session_key(session_key, rsa_public_key)

    # Encodes and writes the key in a base64 file
    open(encrypted_files_default + "encrypted_key.base64", "wb").write(b64encode(enc_session_key))

    # Encodes and writes the encrypted data + the AES nonce in a base64 file
    open(encrypted_files_default + "encrypted_data.base64", "wb").write(b64encode(cipher_aes.nonce + encrypted_data))


def decrypt(data_file, encrypted_key, rsa_private_key):
    encrypted_data_file = b64decode(open(encrypted_files_default + data_file, "rb").read())

    nonce, encrypted_data = [x for x in (encrypted_data_file[0:16], encrypted_data_file[16:])]

    enc_session_key = b64decode(open(encrypted_files_default + encrypted_key, "rb").read())

    session_key = RSA.decrypt_session_key(enc_session_key, rsa_private_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt(encrypted_data)
    open(decrypted_files_default + "final_data.txt", "w").write(data.decode("utf-8"))
