from base64 import b64decode, b64encode
from distutils import core
from Crypto.Cipher import AES
import algoritmos.RSA as RSA
from algoritmos.SessionKey import generate_random_AES_key
import os

dir_name = os.path.dirname(os.path.realpath(__file__))
encrypted_files_default = os.path.join(dir_name, "../results/encrypted/")
decrypted_files_default = os.path.join(dir_name, "../results/decrypted/")


# Funcao que nao precisa das especificaoes dos arquivos de saida
def encrypt_default(data_file, rsa_public_key, sym_key_size):
    print()
    data = open(data_file, "r").read().encode("utf-8")

    # Criptografa a mensagem com a chave de sessao aleatoria gerada
    session_key = generate_random_AES_key(sym_key_size)
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    enc_data = cipher_aes.encrypt(data)
    # Criptografa a chave de sessao aleatoria com a chave publica rsa
    enc_session_key = RSA.encrypt_session_key(session_key, rsa_public_key)

    # Codifica a chave criptografada em base 64 e escreve no arquivo de saida
    open(encrypted_files_default + "encrypted_key.base64", "wb").write(b64encode(enc_session_key))
    # Codifica os dados criptografados e o nonce do aes em base 64 e escreve no arquivo de saida
    open(encrypted_files_default + "encrypted_data.base64", "wb").write(b64encode(cipher_aes.nonce + enc_data))


def encrypt(data_file, rsa_public_key, sym_key_size, enc_data_file_out, enc_key_file_out):
    print()
    data = open(data_file, "r").read().encode("utf-8")

    # Criptografa a mensagem com a chave de sessao aleatoria gerada
    session_key = generate_random_AES_key(sym_key_size)
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    enc_data = cipher_aes.encrypt(data)
    # Criptografa a chave de sessao aleatoria com a chave publica rsa
    enc_session_key = RSA.encrypt_session_key(session_key, rsa_public_key)

    # Codifica a chave criptografada em base 64 e escreve no arquivo de saida
    open(enc_key_file_out, "wb").write(b64encode(enc_session_key))
    # Codifica os dados criptografados e o nonce do aes em base 64 e escreve no arquivo de saida
    open(enc_data_file_out, "wb").write(b64encode(cipher_aes.nonce + enc_data))


# Funcao que nao precisa das especificaoes do arquivo de saida
def decrypt_default(enc_data_file, enc_key_file, rsa_private_key):
    enc_data_file = b64decode(open(enc_data_file, "rb").read())
    enc_session_key = b64decode(open(enc_key_file, "rb").read())

    # Desempacota os dados criptografados e o nonce do aes em suas variaveis
    nonce, enc_data = [x for x in (enc_data_file[0:16], enc_data_file[16:])]

    # Decifra a chave de sessao cifrada com a chave rsa privada
    session_key = RSA.decrypt_session_key(enc_session_key, rsa_private_key)

    # Decifra os dados criptografados com a chave de sessao aleatoria e o nonce
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt(enc_data)
    open(decrypted_files_default + "final_data.txt", "w").write(data.decode("utf-8"))


def decrypt(enc_data_file, enc_key_file, rsa_private_key, data_file_out):
    enc_data_file = b64decode(open(enc_data_file, "rb").read())
    enc_session_key = b64decode(open(enc_key_file, "rb").read())

    # Desempacota os dados criptografados e o nonce do aes em suas variaveis
    nonce, enc_data = [x for x in (enc_data_file[0:16], enc_data_file[16:])]

    # Decifra a chave de sessao cifrada com a chave rsa privada
    session_key = RSA.decrypt_session_key(enc_session_key, rsa_private_key)

    # Decifra os dados criptografados com a chave de sessao aleatoria e o nonce
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt(enc_data)
    open(data_file_out, "w").write(data.decode("utf-8"))
