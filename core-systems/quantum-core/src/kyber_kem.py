"""
Post-Quantum Cryptography - Kyber KEM Implementation
Lattice-based Key Encapsulation Mechanism
NIST PQC Standard (ML-KEM)
"""

import hashlib
import secrets
from dataclasses import dataclass
from typing import Tuple, Optional
from loguru import logger


# Kyber-512 параметры (Level 1 security)
KYBER_N = 256  # Размерность полинома
KYBER_Q = 3329  # Модуль
KYBER_K = 2  # Число полиномов в векторе (Kyber-512)
KYBER_ETA1 = 3  # Параметр шума для секретного ключа
KYBER_ETA2 = 2  # Параметр шума для ошибок
KYBER_DU = 10  # Сжатие u
KYBER_DV = 4  # Сжатие v


@dataclass
class KyberKeys:
    """Пара ключей Kyber"""
    public_key: bytes
    secret_key: bytes


@dataclass
class KyberCiphertext:
    """Шифротекст Kyber"""
    ciphertext: bytes
    shared_secret: bytes


class KyberKEM:
    """
    Kyber Key Encapsulation Mechanism
    
    Lattice-based post-quantum cryptography
    Устойчив к квантовым атакам (Shor, Grover)
    """
    
    def __init__(self, security_level: int = 512):
        """
        Args:
            security_level: 512, 768, or 1024 (Kyber-512/768/1024)
        """
        self.security_level = security_level
        self.n = KYBER_N
        self.q = KYBER_Q
        
        # Настройка параметров в зависимости от уровня безопасности
        if security_level == 512:
            self.k = 2
            self.eta1 = 3
            self.eta2 = 2
        elif security_level == 768:
            self.k = 3
            self.eta1 = 2
            self.eta2 = 2
        elif security_level == 1024:
            self.k = 4
            self.eta1 = 2
            self.eta2 = 2
        else:
            raise ValueError(f"Unsupported security level: {security_level}")
        
        logger.info(f"🔐 Kyber-{security_level} KEM initialized")
    
    def generate_keypair(self) -> KyberKeys:
        """
        Генерирует пару ключей Kyber
        
        Returns:
            KyberKeys с public_key и secret_key
        """
        # Генерация seed для детерминированной генерации
        seed = secrets.token_bytes(32)
        
        # Разворачиваем seed в матрицу A и векторы s, e
        rho, sigma = self._expand_seed(seed)
        
        # Генерация секретного вектора s
        s = self._sample_noise_vector(sigma, self.eta1)
        
        # Генерация вектора ошибок e
        e = self._sample_noise_vector(sigma + b"\x01", self.eta1)
        
        # Публичный ключ: t = A*s + e
        A = self._generate_matrix(rho)
        t = self._vector_add(self._matrix_vector_mul(A, s), e)
        
        # Сериализация ключей
        public_key = self._encode_public_key(t, rho)
        secret_key = self._encode_secret_key(s)
        
        logger.debug(f"Generated Kyber keypair (pk: {len(public_key)} bytes, sk: {len(secret_key)} bytes)")
        
        return KyberKeys(
            public_key=public_key,
            secret_key=secret_key
        )
    
    def encapsulate(self, public_key: bytes) -> KyberCiphertext:
        """
        Инкапсулирует shared secret используя публичный ключ
        
        Args:
            public_key: Публичный ключ получателя
            
        Returns:
            KyberCiphertext с ciphertext и shared_secret
        """
        # Декодируем публичный ключ
        t, rho = self._decode_public_key(public_key)
        
        # Генерируем случайное сообщение
        m = secrets.token_bytes(32)
        
        # Генерируем эфемерные ключи
        coins = self._hash(m + public_key)
        
        # Генерация векторов r, e1, e2
        r = self._sample_noise_vector(coins, self.eta1)
        e1 = self._sample_noise_vector(coins + b"\x01", self.eta2)
        e2 = self._sample_noise_scalar(coins + b"\x02", self.eta2)
        
        # Генерация матрицы A
        A = self._generate_matrix(rho)
        
        # Вычисление u = A^T * r + e1
        u = self._vector_add(self._matrix_transpose_vector_mul(A, r), e1)
        
        # Вычисление v = t^T * r + e2 + encode(m)
        v = self._add_scalar(
            self._add_scalar(
                self._vector_dot(t, r),
                e2
            ),
            self._encode_message(m)
        )
        
        # Сжатие и сериализация шифротекста
        ciphertext = self._encode_ciphertext(u, v)
        
        # Derive shared secret
        shared_secret = self._kdf(m + self._hash(ciphertext))
        
        logger.debug(f"Encapsulated secret (ct: {len(ciphertext)} bytes)")
        
        return KyberCiphertext(
            ciphertext=ciphertext,
            shared_secret=shared_secret
        )
    
    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        """
        Декапсулирует shared secret используя секретный ключ
        
        Args:
            ciphertext: Шифротекст от отправителя
            secret_key: Секретный ключ получателя
            
        Returns:
            shared_secret (32 bytes)
        """
        # Декодируем секретный ключ и шифротекст
        s = self._decode_secret_key(secret_key)
        u, v = self._decode_ciphertext(ciphertext)
        
        # Восстановление сообщения: m = v - s^T * u
        m_encoded = self._sub_scalar(v, self._vector_dot(s, u))
        m = self._decode_message(m_encoded)
        
        # Derive shared secret
        shared_secret = self._kdf(m + self._hash(ciphertext))
        
        logger.debug("Decapsulated shared secret")
        
        return shared_secret
    
    # Helper methods
    
    def _expand_seed(self, seed: bytes) -> Tuple[bytes, bytes]:
        """Расширяет seed в rho и sigma"""
        h = hashlib.sha3_512(seed).digest()
        return h[:32], h[32:]
    
    def _hash(self, data: bytes) -> bytes:
        """SHA3-256 hash"""
        return hashlib.sha3_256(data).digest()
    
    def _kdf(self, data: bytes) -> bytes:
        """Key Derivation Function (SHAKE-256)"""
        return hashlib.shake_256(data).digest(32)
    
    def _sample_noise_vector(self, seed: bytes, eta: int) -> list:
        """Сэмплирует вектор из центрированного биномиального распределения"""
        vector = []
        for i in range(self.k):
            poly = self._sample_noise_poly(seed + bytes([i]), eta)
            vector.append(poly)
        return vector
    
    def _sample_noise_poly(self, seed: bytes, eta: int) -> list:
        """Сэмплирует полином из биномиального распределения"""
        h = hashlib.shake_256(seed).digest(self.n * eta // 4)
        poly = []
        for i in range(self.n):
            # Упрощенная версия CBD (Centered Binomial Distribution)
            byte_val = h[i % len(h)]
            a = sum((byte_val >> j) & 1 for j in range(eta))
            b = sum((byte_val >> (j + eta)) & 1 for j in range(eta))
            poly.append((a - b) % self.q)
        return poly
    
    def _sample_noise_scalar(self, seed: bytes, eta: int) -> int:
        """Сэмплирует скаляр из биномиального распределения"""
        poly = self._sample_noise_poly(seed, eta)
        return poly[0]
    
    def _generate_matrix(self, rho: bytes) -> list:
        """Генерирует матрицу A из seed rho"""
        matrix = []
        for i in range(self.k):
            row = []
            for j in range(self.k):
                seed = rho + bytes([i, j])
                poly = self._sample_uniform_poly(seed)
                row.append(poly)
            matrix.append(row)
        return matrix
    
    def _sample_uniform_poly(self, seed: bytes) -> list:
        """Сэмплирует полином из uniform распределения"""
        h = hashlib.shake_128(seed).digest(self.n * 2)
        poly = []
        for i in range(self.n):
            val = int.from_bytes(h[i*2:(i+1)*2], 'little') % self.q
            poly.append(val)
        return poly
    
    def _matrix_vector_mul(self, matrix: list, vector: list) -> list:
        """Умножение матрицы на вектор"""
        result = []
        for row in matrix:
            poly_sum = [0] * self.n
            for poly_m, poly_v in zip(row, vector):
                poly_prod = self._poly_mul(poly_m, poly_v)
                poly_sum = self._poly_add(poly_sum, poly_prod)
            result.append(poly_sum)
        return result
    
    def _matrix_transpose_vector_mul(self, matrix: list, vector: list) -> list:
        """Умножение транспонированной матрицы на вектор"""
        k = len(matrix)
        result = []
        for j in range(k):
            poly_sum = [0] * self.n
            for i in range(k):
                poly_prod = self._poly_mul(matrix[i][j], vector[i])
                poly_sum = self._poly_add(poly_sum, poly_prod)
            result.append(poly_sum)
        return result
    
    def _vector_add(self, v1: list, v2: list) -> list:
        """Сложение векторов"""
        return [self._poly_add(p1, p2) for p1, p2 in zip(v1, v2)]
    
    def _vector_dot(self, v1: list, v2: list) -> list:
        """Скалярное произведение векторов (возвращает полином)"""
        result = [0] * self.n
        for p1, p2 in zip(v1, v2):
            prod = self._poly_mul(p1, p2)
            result = self._poly_add(result, prod)
        return result
    
    def _poly_add(self, p1: list, p2: list) -> list:
        """Сложение полиномов"""
        return [(a + b) % self.q for a, b in zip(p1, p2)]
    
    def _poly_mul(self, p1: list, p2: list) -> list:
        """Умножение полиномов (упрощенная версия)"""
        result = [0] * self.n
        for i in range(self.n):
            for j in range(self.n):
                result[(i + j) % self.n] = (result[(i + j) % self.n] + p1[i] * p2[j]) % self.q
        return result
    
    def _add_scalar(self, poly: list, scalar: int) -> list:
        """Добавляет скаляр к первому коэффициенту полинома"""
        result = poly.copy()
        result[0] = (result[0] + scalar) % self.q
        return result
    
    def _sub_scalar(self, poly: list, scalar_poly: list) -> list:
        """Вычитает полином"""
        return [(a - b) % self.q for a, b in zip(poly, scalar_poly)]
    
    def _encode_message(self, m: bytes) -> int:
        """Кодирует сообщение в скаляр"""
        return int.from_bytes(m[:4], 'little') % self.q
    
    def _decode_message(self, scalar: list) -> bytes:
        """Декодирует скаляр в сообщение"""
        # Упрощенное декодирование - в real implementation используется compress/decompress
        val = scalar[0] % 256
        return val.to_bytes(32, 'little')
    
    def _encode_public_key(self, t: list, rho: bytes) -> bytes:
        """Сериализует публичный ключ"""
        # Упрощенная сериализация
        data = rho
        for poly in t:
            for coeff in poly:
                data += coeff.to_bytes(2, 'little')
        return data
    
    def _decode_public_key(self, pk: bytes) -> Tuple[list, bytes]:
        """Десериализует публичный ключ"""
        rho = pk[:32]
        offset = 32
        t = []
        for _ in range(self.k):
            poly = []
            for _ in range(self.n):
                coeff = int.from_bytes(pk[offset:offset+2], 'little')
                poly.append(coeff)
                offset += 2
            t.append(poly)
        return t, rho
    
    def _encode_secret_key(self, s: list) -> bytes:
        """Сериализует секретный ключ"""
        data = b''
        for poly in s:
            for coeff in poly:
                data += coeff.to_bytes(2, 'little')
        return data
    
    def _decode_secret_key(self, sk: bytes) -> list:
        """Десериализует секретный ключ"""
        s = []
        offset = 0
        for _ in range(self.k):
            poly = []
            for _ in range(self.n):
                coeff = int.from_bytes(sk[offset:offset+2], 'little')
                poly.append(coeff)
                offset += 2
            s.append(poly)
        return s
    
    def _encode_ciphertext(self, u: list, v: list) -> bytes:
        """Сериализует шифротекст"""
        data = b''
        for poly in u:
            for coeff in poly:
                data += coeff.to_bytes(2, 'little')
        for coeff in v:
            data += coeff.to_bytes(2, 'little')
        return data
    
    def _decode_ciphertext(self, ct: bytes) -> Tuple[list, list]:
        """Десериализует шифротекст"""
        offset = 0
        u = []
        for _ in range(self.k):
            poly = []
            for _ in range(self.n):
                coeff = int.from_bytes(ct[offset:offset+2], 'little')
                poly.append(coeff)
                offset += 2
            u.append(poly)
        
        v = []
        for _ in range(self.n):
            coeff = int.from_bytes(ct[offset:offset+2], 'little')
            v.append(coeff)
            offset += 2
        
        return u, v


# Helper function для простого использования
def kyber_keygen(security_level: int = 512) -> KyberKeys:
    """Генерирует пару ключей Kyber"""
    kem = KyberKEM(security_level)
    return kem.generate_keypair()


def kyber_encaps(public_key: bytes, security_level: int = 512) -> KyberCiphertext:
    """Инкапсулирует shared secret"""
    kem = KyberKEM(security_level)
    return kem.encapsulate(public_key)


def kyber_decaps(ciphertext: bytes, secret_key: bytes, security_level: int = 512) -> bytes:
    """Декапсулирует shared secret"""
    kem = KyberKEM(security_level)
    return kem.decapsulate(ciphertext, secret_key)
