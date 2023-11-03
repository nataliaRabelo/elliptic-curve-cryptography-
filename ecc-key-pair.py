# Para compilar e executar: python ecc-key-pair.py

import time
import os
import hashlib

class SecureEllipticCurve:
    # Coeficientes para uma curva elíptica segura (exemplo: curva secp256k1 usada pelo Bitcoin)
    def __init__(self):
        self.p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        self.a = 0
        self.b = 7
        self.G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
                  0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
        self.n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

    # O(log p) - usa o algoritmo de Euclides estendido para o inverso multiplicativo
    def invert(self, val):
        # Calcula o inverso multiplicativo usando o algoritmo de Euclides estendido
        return pow(val, -1, self.p)

    # O(log p) - opera com números grandes e utiliza inverso multiplicativo
    def add_points(self, P, Q):
        if P == Q:
            lmbda = ((3 * P[0] ** 2 + self.a) * self.invert(2 * P[1])) % self.p
        else:
            lmbda = ((Q[1] - P[1]) * self.invert(Q[0] - P[0])) % self.p
        x_r = (lmbda ** 2 - P[0] - Q[0]) % self.p
        y_r = (lmbda * (P[0] - x_r) - P[1]) % self.p
        return x_r, y_r

    # O(log k) - duplicação e adição de pontos dependem do tamanho do escalar 'k'
    def multiply_point(self, k, P):
        # Multiplica o ponto P pelo escalar k usando o método de duplicação e adição
        R = None
        while k:
            if k & 1:
                R = P if R is None else self.add_points(R, P)
            P = self.add_points(P, P)
            k >>= 1
        return R

    # O(log n) para a multiplicação de ponto, assumindo que a geração de números aleatórios é O(1)
    def generate_keypair(self):
        # Gera um par de chaves usando a curva elíptica
        private_key = int.from_bytes(os.urandom(32), 'big') % self.n
        public_key = self.multiply_point(private_key, self.G)
        return private_key, public_key

     # O(1) - a complexidade do hash é constante e não depende do tamanho do input
    def hash_point(self, P):
        # Hashes um ponto em curva elíptica
        x_str = hex(P[0])[2:].rjust(64, '0')
        y_str = hex(P[1])[2:].rjust(64, '0')
        return hashlib.sha256((x_str + y_str).encode()).hexdigest()

# Iniciar a cronometragem para medir o tempo de execução das operações na curva.
start_time = time.time()

# Exemplo de uso
curve = SecureEllipticCurve()
private_key, public_key = curve.generate_keypair()
print("Chave privada:", hex(private_key))
print("Chave pública:", public_key)


hash_of_point = curve.hash_point(public_key)  # Cria um hash da chave pública
print("Hash SHA-256 do ponto na curva (chave pública):", hash_of_point)

# Parar a cronometragem e calcular o tempo de execução.
execution_time = time.time() - start_time
print("Tempo de execução:", execution_time)

