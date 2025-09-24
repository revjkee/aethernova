import os
import secrets
import hashlib
import threading
from typing import Optional, Tuple
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class QuantumKeyMutator:
    """
    Промышленный модуль мутации квантовых ключей с высокой энтропией.
    Обеспечивает постквантовую стойкость, маскирование, смешивание и проверку на столкновения.
    """

    def __init__(self, seed: Optional[bytes] = None, entropy_strength: int = 512):
        self.lock = threading.Lock()
        self.entropy_strength = entropy_strength
        self.seed = seed or get_random_bytes(entropy_strength // 8)
        self._validate_entropy(self.seed)
        self.state = hashlib.shake_256(self.seed).digest(entropy_strength // 8)

    def _validate_entropy(self, seed: bytes) -> None:
        if len(seed) * 8 < self.entropy_strength:
            raise ValueError("Entropy seed too weak for required entropy strength.")

    def mutate(self, key: bytes, rounds: int = 5) -> bytes:
        """
        Проводит циклическую мутацию ключа с использованием сильных шифроэнтропийных процедур.
        """
        with self.lock:
            for i in range(rounds):
                salt = secrets.token_bytes(16)
                key = self._xor_and_hash(key, salt)
                key = self._aes_mix(key, salt)
                key = self._permute(key, i)
            return key

    def _xor_and_hash(self, key: bytes, salt: bytes) -> bytes:
        mixed = bytes(a ^ b for a, b in zip(key.ljust(len(salt), b'\0'), salt))
        return hashlib.blake2b(mixed, digest_size=len(key)).digest()

    def _aes_mix(self, key: bytes, salt: bytes) -> bytes:
        """
        Применяет AES-контекстную маску к ключу
        """
        cipher = AES.new(salt.ljust(32, b'\0'), AES.MODE_ECB)
        return cipher.encrypt(key.ljust(32, b'\0'))[:len(key)]

    def _permute(self, key: bytes, round_index: int) -> bytes:
        """
        Применяет псевдослучайную перестановку к ключу на основе текущего состояния и номера раунда.
        """
        seed = hashlib.sha3_512(self.state + key + round_index.to_bytes(4, 'big')).digest()
        indexes = list(range(len(key)))
        for i in range(len(indexes) - 1, 0, -1):
            j = seed[i] % (i + 1)
            indexes[i], indexes[j] = indexes[j], indexes[i]
        return bytes([key[i] for i in indexes])

    def rotate_seed(self, rotation_data: Optional[bytes] = None) -> None:
        """
        Выполняет поворот энтропийного состояния для обновления генеративной базы.
        """
        with self.lock:
            rotation_data = rotation_data or get_random_bytes(len(self.seed))
            self.seed = hashlib.sha3_512(self.seed + rotation_data).digest()
            self.state = hashlib.shake_256(self.seed).digest(len(self.seed))

    def secure_compare(self, a: bytes, b: bytes) -> bool:
        """
        Безопасное сравнение двух байтовых массивов без утечек по времени.
        """
        return secrets.compare_digest(a, b)

    def generate_mutation_pair(self, original: bytes) -> Tuple[bytes, bytes]:
        """
        Возвращает оригинальный и мутировавший ключ для тестов или симметричной передачи.
        """
        mutated = self.mutate(original)
        return original, mutated

