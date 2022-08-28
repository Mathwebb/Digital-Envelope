import sys
sys.path.insert(1, 'algoritmos')

import algoritmos.AES as AES, algoritmos.DES as DES, algoritmos.RC4 as RC4
from Crypto.PublicKey import RSA

if(len(sys.argv)!=5):
    if(len(sys.argv)<5):
        print("Falta ", 5 - len(sys.argv)," argumento(s) para criação do envelope digital.")
    else:
        print("Tem ", len(sys.argv)-5," argumento(s) a mais para criação do envelope digital.")
    exit()

mensagem_cripto = sys.argv[1]
chave_cripto = sys.argv[2]
chave_privada = sys.argv[3]
algo_simetrico = sys.argv[4]

try:
    open(chave_cripto,'r')
    open(mensagem_cripto,'r')
    open(chave_privada,'r')
except Exception as e:
    print("Arquivo não encontrado.")
    print(e)
    exit()

chave_privada = RSA.import_key(open(chave_privada, "rb").read())

if(algo_simetrico.upper()=="AES"):
    AES.decrypt(mensagem_cripto, chave_cripto, chave_privada)
elif(algo_simetrico.upper()=="DES"):
    DES.decrypt(mensagem_cripto, chave_cripto, chave_privada)
elif(algo_simetrico.upper()=="RC4"):
    RC4.decrypt(mensagem_cripto, chave_cripto, chave_privada)
else:
    print("O algoritmo simétrico dado é inválido")


