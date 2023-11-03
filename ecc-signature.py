# Pré-requisitos:
# pip install cryptography
#
# Para compilar e executar: python ecc-signature.py

import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

# Geração de chaves usando ECC
def generate_ecc_keys():
    # Gera um par de chaves privada e pública usando a curva P-256
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

# Criar uma assinatura digital usando a chave privada
def sign_data(private_key, data):
    # Assina os dados usando a chave privada e ECDSA com SHA256
    return private_key.sign(data, ec.ECDSA(hashes.SHA256()))

# Verificar uma assinatura digital usando a chave pública
def verify_signature(public_key, signature, data):
    # Verifica a assinatura dos dados usando a chave pública e ECDSA com SHA256
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except:
        return False

# Iniciar a cronometragem para medir o tempo de execução das operações na curva.
start_time = time.time()

# Exemplo de uso
private_key, public_key = generate_ecc_keys()

# Assumindo que 'data' é a informação que você deseja assinar e verificar.
data = b"Data to be signed"

signature = sign_data(private_key, data)
print("Signature:", signature)

# Verificar a assinatura
is_valid = verify_signature(public_key, signature, data)
print("Is the signature valid?", is_valid)

# Parar a cronometragem e calcular o tempo de execução.
execution_time = time.time() - start_time
print("Tempo de execução:", execution_time)
