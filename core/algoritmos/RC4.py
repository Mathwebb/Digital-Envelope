from time import sleep
from Crypto.Cipher import ARC4
from Crypto.Hash import SHA256, HMAC
from Crypto.Random import get_random_bytes
from base64 import b64decode, b64encode
import SessionKey
from Crypto.PublicKey import RSA
import RSA as rsa_local

encrypted_files_default = "./results/encrypted/"
decrypted_files_default = "./results/decrypted/"

def encrypt(data_file, rsa_public_key):
    data = open(data_file, "r").read().encode("utf-8")

    # Gera chave de sessao e nonce aleatorios
    nonce = get_random_bytes(16)
    session_key = SessionKey.generate_random_RC4_key()
    # Criptografa a mensagem com a chave de sessao e o nonce aleatorio gerados
    stream_key = HMAC.new(session_key + nonce, digestmod=SHA256).digest()
    cipher = ARC4.new(stream_key)
    enc_data = cipher.encrypt(data)
    # Criptografa a chave de sessao aleatoria com a chave publica rsa
    enc_session_key = rsa_local.encrypt_session_key(session_key, rsa_public_key)

    # Codifica a chave criptografada em base 64 e escreve no arquivo de saida
    open(encrypted_files_default + "encrypted_key.base64", "wb").write(b64encode(enc_session_key))
    # Codifica os dados criptografados e o nonce gerado em base 64 e escreve no arquivo de saida
    open(encrypted_files_default + "encrypted_data.base64", "wb").write(b64encode(nonce + enc_data))

def decrypt(enc_data_file, enc_key_file, rsa_private_key):
    enc_data_file = b64decode(open(enc_data_file, "rb").read())
    enc_session_key = b64decode(open(enc_key_file, "rb").read())

    # Desempacota os dados criptografados e o nonce gerado em suas variaveis
    nonce, enc_data = [x for x in (enc_data_file[0:16], enc_data_file[16:])]

    # Decifra a chave de sessao cifrada com a chave rsa privada
    session_key = rsa_local.decrypt_session_key(enc_session_key, rsa_private_key)

    # Decifra os dados criptografados com a chave de sessao aleatoria e o nonce
    stream_key = HMAC.new(session_key + nonce, digestmod=SHA256).digest()
    cipher = ARC4.new(stream_key)
    data = cipher.decrypt(enc_data)
    open(decrypted_files_default + "final_data.txt", "w").write(data.decode("utf-8"))

if __name__ == "__main__":
    encrypt("./Exemplos/temp/dados.txt", RSA.import_key(open("./core/chaves_RSA/public.pem", "rb").read()))
    decrypt("./core/results/encrypted/encrypted_data.base64", "./core/results/encrypted/encrypted_key.base64",
            RSA.import_key(open("./core/chaves_RSA/private.pem", "rb").read()))
