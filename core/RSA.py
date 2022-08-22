from Crypto.PublicKey import RSA


def generate_rsa_keys(key_size: int) -> dict:
    key = RSA.generate(key_size)
    public_key = key.public_key().export_key()
    private_key = key.export_key()
    return {"public_key": public_key, "private_key": private_key}


def encrypt_session_key(self, session_key):
    pass


def decrypt_session_key(self, enc_session_key):
    pass
