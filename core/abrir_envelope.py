import sys
sys.path.insert(1, 'algoritmos')

import algoritmos.AES as AES, algoritmos.DES as DES, algoritmos.RC4 as RC4
from Crypto.PublicKey import RSA

if len(sys.argv) == 5:
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
        AES.decrypt_default(mensagem_cripto, chave_cripto, chave_privada)
    elif(algo_simetrico.upper()=="DES"):
        DES.decrypt_default(mensagem_cripto, chave_cripto, chave_privada)
    elif(algo_simetrico.upper()=="RC4"):
        RC4.decrypt_default(mensagem_cripto, chave_cripto, chave_privada)
    else:
        print("O algoritmo simétrico dado é inválido")
elif len(sys.argv) == 6:
    mensagem_cripto = sys.argv[1]
    chave_cripto = sys.argv[2]
    chave_privada = sys.argv[3]
    arq_dados_saida = sys.argv[4]
    algo_simetrico = sys.argv[5]

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
        AES.decrypt(mensagem_cripto, chave_cripto, chave_privada, arq_dados_saida)
    elif(algo_simetrico.upper()=="DES"):
        DES.decrypt(mensagem_cripto, chave_cripto, chave_privada, arq_dados_saida)
    elif(algo_simetrico.upper()=="RC4"):
        RC4.decrypt(mensagem_cripto, chave_cripto, chave_privada, arq_dados_saida)
    else:
        print("O algoritmo simétrico dado é inválido")
else:
    print('Argumentos insuficientes para a criacao do envelope digital')

