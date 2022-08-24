from Crypto.Random import get_random_bytes

def generate_random_AES_key(size):
    if size/8 not in [16, 24, 32]:
        raise ValueError('Tamanho de chave errado. Precisa ser: 128, 192 ou 256.')
    return get_random_bytes(int(size/8))

def generate_random_DES_key(size):
    if size/8 != 8:
        raise ValueError('Tamanho de chave errado. Precisa ser: 64.')
    return get_random_bytes(int(size/8))
