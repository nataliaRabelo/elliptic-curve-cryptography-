# Pré-requisitos:
# pip install cryptography
#
# Para compilar e executar: python diffie-hellman-ecc.py

import time
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Geração da chave privada é uma operação constante em termos de tempo, O(1)
def generate_ecc_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    return private_key

# Serialização da chave pública é uma operação constante, O(1).
def serialize_public_key(public_key):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem

# Desserialização da chave pública é uma operação constante, O(1)
def deserialize_public_key(pem):
    public_key = serialization.load_pem_public_key(pem, backend=default_backend())
    return public_key

# Criação do segredo compartilhado é uma operação constante, O(1).
def create_shared_secret(private_key, peer_public_key):
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    # Derivação da chave com HKDF é O(n) para a saída de n bytes.
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_secret)
    return derived_key

def encrypt_message(key, plaintext):
    # AES requer um vetor de inicialização (iv) que é único para cada cifragem. O(n)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv, ciphertext

def decrypt_message(key, iv, ciphertext): # O(n)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Iniciar a cronometragem para medir o tempo de execução das operações na curva.
start_time = time.perf_counter() 

# Alice cria seu par de chaves
alice_private_key = generate_ecc_key_pair()
alice_public_key = alice_private_key.public_key()

# Bob cria seu par de chaves
bob_private_key = generate_ecc_key_pair()
bob_public_key = bob_private_key.public_key()

# Alice e Bob trocam suas chaves públicas e criam um segredo compartilhado
alice_shared_secret = create_shared_secret(alice_private_key, bob_public_key)
bob_shared_secret = create_shared_secret(bob_private_key, alice_public_key)

# Verifica se ambos os segredos compartilhados são iguais
assert alice_shared_secret == bob_shared_secret
print("ECDH shared secret established successfully!")
print("Alice Shared Secret: " + str(alice_shared_secret))
print("Bob Shared Secret: " + str(bob_shared_secret))

# Parar a cronometragem e calcular o tempo de execução.
execution_time = time.perf_counter() - start_time
print("Tempo de execução:", execution_time)

# Agora vamos cifrar uma mensagem com a chave compartilhada
message = b"A mensagem secreta de Alice para Bob"
iv, encrypted_message = encrypt_message(alice_shared_secret, message)
print("Encrypted Message:", encrypted_message)

# Para decifrar, Bob usaria a mesma chave compartilhada e o iv que Alice usou para cifrar a mensagem.
decrypted_message = decrypt_message(bob_shared_secret, iv, encrypted_message)
print("Decrypted Message:", decrypted_message)