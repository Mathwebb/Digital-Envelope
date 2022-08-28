import sys
sys.path.insert(1, 'algoritmos')

import algoritmos.AES as AES, algoritmos.DES as DES, algoritmos.RC4 as RC4
from Crypto.PublicKey import RSA

if len(sys.argv) == 4:
    arquivo = sys.argv[1]
    chave_publica = sys.argv[2]
    algo_simetrico = sys.argv[3]

    try:
        open(arquivo,'r')
        open(chave_publica,'r')
    except Exception as e:
        print("Arquivo não encontrado.")
        exit()

    chave_publica = RSA.import_key(open(chave_publica, "rb").read())

    if(algo_simetrico.upper()=="AES"):
        AES.encrypt_default(arquivo, chave_publica, 128)
    elif(algo_simetrico.upper()=="DES"):
        DES.encrypt_default(arquivo, chave_publica)
    elif(algo_simetrico.upper()=="RC4"):
        RC4.encrypt_default(arquivo, chave_publica)
    else:
        print("O algoritmo simétrico dado é inválido")
elif len(sys.argv)==6:
    arquivo = sys.argv[1]
    chave_publica = sys.argv[2]
    arq_dados_saida = sys.argv[3]
    arq_chave_saida = sys.argv[4]
    algo_simetrico = sys.argv[5]
    
    try:
        open(arquivo,'r')
        open(chave_publica,'r')
    except Exception as e:
        print("Arquivo não encontrado.")
        exit()
    
    chave_publica = RSA.import_key(open(chave_publica, "rb").read())

    if(algo_simetrico.upper()=="AES"):
        AES.encrypt(arquivo, chave_publica, 128, arq_dados_saida, arq_chave_saida)
    elif(algo_simetrico.upper()=="DES"):
        DES.encrypt(arquivo, chave_publica, arq_dados_saida, arq_chave_saida)
    elif(algo_simetrico.upper()=="RC4"):
        RC4.encrypt(arquivo, chave_publica, arq_dados_saida, arq_chave_saida)
    else:
        print("O algoritmo simétrico dado é inválido")
else:
    print('Argumentos insuficientes para a criacao do envelope digital')
