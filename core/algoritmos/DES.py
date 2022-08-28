from base64 import b64decode, b64encode
from Crypto.Cipher import DES
import algoritmos.RSA as RSA
from algoritmos.SessionKey import generate_random_DES_key

encrypted_files_default = "results/encrypted/"
decrypted_files_default = "results/decrypted/"


def encrypt(data_file, rsa_public_key):
    data = open(data_file, 'r').read().encode("utf-8")

    # Criptografa a mensagem com a chave de sessao aleatoria gerada
    session_key = generate_random_DES_key(64)
    cipher = DES.new(session_key, DES.MODE_OFB)
    enc_data = cipher.encrypt(data)
    # Criptografa a chave de sessao aleatoria com a chave publica rsa
    enc_session_key = RSA.encrypt_session_key(session_key, rsa_public_key)

    # Codifica a chave criptografada em base 64 e escreve no arquivo de saida
    open(encrypted_files_default + "encrypted_key.base64", "wb").write(b64encode(enc_session_key))
    # Codifica os dados criptografados e o iv do des em base 64 e escreve no arquivo de saida
    open(encrypted_files_default + "encrypted_data.base64", "wb").write(b64encode(cipher.iv + enc_data))


def decrypt(enc_data_file, enc_key_file, rsa_private_key):
    enc_data_file = b64decode(open(enc_data_file, "rb").read())
    enc_session_key = b64decode(open(enc_key_file, "rb").read())

    # Desempacota os dados criptografados e o initialization vector do des em suas variaveis
    iv, enc_data = [x for x in (enc_data_file[0:8], enc_data_file[8:])]

    # Decifra a chave de sessao cifrada com a chave rsa privada
    session_key = RSA.decrypt_session_key(enc_session_key, rsa_private_key)

    # Decifra os dados criptografados com a chave de sessao aleatoria e o nonce
    cipher = DES.new(session_key, DES.MODE_OFB, iv=iv)
    data = cipher.decrypt(enc_data)
    open(decrypted_files_default + "final_data.txt", "w").write(data.decode("utf-8"))
