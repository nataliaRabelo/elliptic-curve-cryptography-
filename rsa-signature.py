# Pré-requisitos:
# pip install cryptography
#
# Para compilar e executar: python rsa-signature.py

import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Geração de chaves usando RSA
def generate_rsa_keys():
    # Complexidade: Subexponencial, pois a geração de chaves RSA envolve a geração de dois números primos grandes
    # Gera um par de chaves privada e pública usando RSA com um tamanho de chave de 2048 bits
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Criar uma assinatura digital usando a chave privada
def sign_data(private_key, data):
    # Complexidade: O(n^3), assumindo que 'n' é o número de bits da chave, devido à exponenciação modular para assinatura
    # Assina os dados usando a chave privada e RSA com PSS padding e SHA256
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# Verificar uma assinatura digital usando a chave pública
def verify_signature(public_key, signature, data):
    # Complexidade: O(n^3), similar à assinatura, devido à operação de verificação que também envolve exponenciação modular
    # Verifica a assinatura dos dados usando a chave pública e RSA com PSS padding e SHA256
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(e)
        return False

# Iniciar a cronometragem para medir o tempo de execução das operações.
start_time = time.time()

# Exemplo de uso
private_key, public_key = generate_rsa_keys()

# Assumindo que 'data' é a informação que você deseja assinar e verificar.
data = b"Data to be signed"

signature = sign_data(private_key, data)
print("Signature:", signature.hex())

# Verificar a assinatura
is_valid = verify_signature(public_key, signature, data)
print("Is the signature valid?", is_valid)

# Parar a cronometragem e calcular o tempo de execução.
execution_time = time.time() - start_time
print("Execution time:", execution_time)
