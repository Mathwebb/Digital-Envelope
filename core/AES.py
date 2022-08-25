from base64 import b64decode, b64encode
from Crypto.Cipher import AES
import RSA, os, SessionKey


def encrypt(data_file, rsa_public_key, sym_key_size):
    data = open(data_file, "r").read().encode("utf-8")

    # Encrypt the message with the session key
    session_key = SessionKey.generate_random_key(sym_key_size)
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    encrypted_data = cipher_aes.encrypt(data)

    enc_session_key = RSA.encrypt_session_key(session_key, rsa_public_key)

    # Encodes and writes the key in a base64 file
    open("core/results/encrypted/encrypted_key.base64", "wb").write(b64encode(enc_session_key))

    # Uses a temporary binary file to write the nonce + the encrypted data to the base64
    encrypted_data_temp = open("encrypted_data_temp.bin", "wb+")
    [encrypted_data_temp.write(x) for x in (cipher_aes.nonce, encrypted_data)]
    encrypted_data_temp.seek(0)

    open("core/results/encrypted/encrypted_data.base64", "wb").write(b64encode(encrypted_data_temp.read()))
    encrypted_data_temp.close()
    os.remove("encrypted_data_temp.bin")


def decrypt(data_file, encrypted_key, rsa_private_key):
    encrypted_data_file = open(f"core/results/encrypted/{data_file}", "rb")

    encrypted_data_temp = open("encrypted_data_temp.bin", "wb+")
    encrypted_data_temp.write(b64decode(encrypted_data_file.read()))
    encrypted_data_temp.seek(0)

    nonce, encrypted_data = [encrypted_data_temp.read(x) for x in (16, -1)]

    encrypted_data_file.close()
    encrypted_data_temp.close()
    os.remove("encrypted_data_temp.bin")

    enc_session_key = b64decode(open(f"core/results/encrypted/{encrypted_key}", "rb").read())

    session_key = RSA.decrypt_session_key(enc_session_key, rsa_private_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt(encrypted_data)
    open("core/results/decrypted/final_data.txt", "w").write(data.decode("utf-8"))
