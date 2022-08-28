import sys
sys.path.insert(1, 'algoritmos')

from algoritmos import RSA

if len(sys.argv) == 4:
    dict = RSA.generate_rsa_keys(int(sys.argv[3]))
    open(sys.argv[1], 'wb').write(dict["public_key"])
    open(sys.argv[2], 'wb').write(dict["private_key"])
else:
    print("Argumentos insuficientes para a geracao das chaves RSA, sao necessarios 3 argumentos " +
        "(arquivo da chave publica, arquivo da chave privada, tamanho das chaves RSA)")
