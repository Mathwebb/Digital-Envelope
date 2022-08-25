from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def generate_rsa_keys(key_size: int) -> dict:
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return {"public_key": public_key, "private_key": private_key}


def encrypt_session_key(session_key, rsa_public_key):
    cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
    enc_session_key = cipher_rsa.encrypt(session_key)
    return enc_session_key


def decrypt_session_key(enc_session_key, rsa_private_key):
    cipher_rsa = PKCS1_OAEP.new(rsa_private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)
    return session_key
