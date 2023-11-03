# Pré-requisitos:
# pip install cryptography
#
# Para compilar e executar: python rsa-key-pair.py

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import time

# Classe para geração de chaves RSA com comentários sobre complexidade
class RSAKeyPairGenerator:
    # Inicializa a geração de chaves com um tamanho específico
    # Complexidade: A geração de números primos é subexponencial, mas não exatamente O(log n).
    def __init__(self, key_size=2048):
        self.key_size = key_size

    def generate_keys(self):
        # Gera um par de chaves RSA (privada e pública)
        # Complexidade: Subexponencial, frequentemente estimada como O(n^3)
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=default_backend()
        )
        return private_key, private_key.public_key()

    def serialize_key(self, key):
        # Serializa a chave para o formato PEM
        # Complexidade: O(1), pois é uma operação direta de codificação.
        if isinstance(key, rsa.RSAPrivateKey):
            return key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        elif isinstance(key, rsa.RSAPublicKey):
            return key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

# Iniciar cronometragem para medir o tempo de execução da geração de chaves RSA.
start_time = time.perf_counter()

# Exemplo de uso
key_pair_generator = RSAKeyPairGenerator(key_size=2048)
private_key, public_key = key_pair_generator.generate_keys()

# Serialização das chaves para formato PEM
private_pem = key_pair_generator.serialize_key(private_key)
public_pem = key_pair_generator.serialize_key(public_key)

# Parar cronometragem e calcular o tempo de execução.
execution_time = time.perf_counter() - start_time

# Imprimir as chaves e o tempo de execução
print("Private key:", private_pem.decode())
print("Public key:", public_pem.decode())
print("Execution time:", execution_time)

