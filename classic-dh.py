# Pré-requisitos:
# pip install cryptography
#
# Para compilar e executar: python classic-dh.py

import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization

# Função para gerar um par de chaves (Complexidade: O(log n))
# A complexidade é dominada pelo cálculo da chave pública a partir da chave privada,
# que envolve operações de exponenciação modular.
def generate_dh_key_pair(parameters):
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_key, pem

# Função para criar um segredo compartilhado usando DH (Complexidade: O(log n))
# A operação de troca envolve exponenciação modular, que é O(log n).
def create_dh_shared_secret(private_key, peer_public_key_pem):
    peer_public_key = serialization.load_pem_public_key(
        peer_public_key_pem,
        backend=default_backend()
    )
    shared_secret = private_key.exchange(peer_public_key)
    # Derivação de chave com HKDF (Complexidade: O(n) para saída de n bytes)
    # Aqui, 'n' é a quantidade de bytes que queremos derivar.
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_secret)
    return derived_key

# Iniciar a cronometragem.
start_time = time.perf_counter() 

# Gerando parâmetros DH (Complexidade: Superpolinomial/Subexponencial)
# Esta é uma operação complexa que envolve a geração de números primos grandes e seguros.
parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

# Exemplo de uso para DH
alice_private_key, alice_public_key_pem = generate_dh_key_pair(parameters)
bob_private_key, bob_public_key_pem = generate_dh_key_pair(parameters)

# Alice e Bob trocam suas chaves públicas e criam um segredo compartilhado
alice_shared_secret = create_dh_shared_secret(alice_private_key, bob_public_key_pem)
bob_shared_secret = create_dh_shared_secret(bob_private_key, alice_public_key_pem)

# Parar cronômetro
execution_time = time.perf_counter() - start_time

# Verificar se os segredos compartilhados são iguais
if alice_shared_secret == bob_shared_secret:
    print("DH shared secret established successfully!")
    print(f"Shared secret: {alice_shared_secret.hex()}")
else:
    print("Failed to establish a shared secret.")

# Imprimir chaves públicas e tempo de execução
print(f"Execution time: {execution_time} seconds")

