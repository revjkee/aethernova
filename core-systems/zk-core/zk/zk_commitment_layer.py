# zk-core/zk/zk_commitment_layer.py

import os
import hashlib
import logging
from typing import Tuple, Optional

from Crypto.Util import number
from Crypto.Random import get_random_bytes

logger = logging.getLogger("zk_commitment_layer")
logger.setLevel(logging.INFO)


class PedersenCommitment:
    def __init__(self, p: int, g: int, h: int):
        """
        Параметры: p — большое простое, g/h — генераторы.
        """
        self.p = p
        self.g = g
        self.h = h

    def commit(self, value: int, randomness: Optional[int] = None) -> Tuple[int, int]:
        """
        Генерация обязательства (commitment) и использованной случайности.
        """
        r = randomness or number.getRandomRange(1, self.p - 1)
        commitment = (pow(self.g, value, self.p) * pow(self.h, r, self.p)) % self.p
        return commitment, r

    def verify(self, commitment: int, value: int, r: int) -> bool:
        """
        Проверка корректности обязательства.
        """
        expected = (pow(self.g, value, self.p) * pow(self.h, r, self.p)) % self.p
        return expected == commitment


class ElGamalCommitment:
    def __init__(self, p: int, g: int, h: int):
        self.p = p
        self.g = g
        self.h = h

    def commit(self, value: int) -> Tuple[int, int, int]:
        """
        Генерация ElGamal-коммитмента.
        """
        r = number.getRandomRange(1, self.p - 1)
        c1 = pow(self.g, r, self.p)
        c2 = (value * pow(self.h, r, self.p)) % self.p
        return c1, c2, r

    def verify(self, c1: int, c2: int, value: int, r: int) -> bool:
        expected_c1 = pow(self.g, r, self.p)
        expected_c2 = (value * pow(self.h, r, self.p)) % self.p
        return (c1 == expected_c1) and (c2 == expected_c2)


class CommitmentFactory:
    """
    Автоматическая генерация параметров и выбор схемы.
    """

    def __init__(self):
        self.p = number.getPrime(2048)
        self.g = 2
        self.h = number.getRandomRange(2, self.p - 1)

    def create_pedersen(self) -> PedersenCommitment:
        return PedersenCommitment(p=self.p, g=self.g, h=self.h)

    def create_elgamal(self) -> ElGamalCommitment:
        return ElGamalCommitment(p=self.p, g=self.g, h=self.h)


def hash_to_int(data: bytes) -> int:
    return int.from_bytes(hashlib.sha256(data).digest(), byteorder="big")


# Singleton для интеграции
commitment_factory = CommitmentFactory()
pedersen_commit = commitment_factory.create_pedersen()
elgamal_commit = commitment_factory.create_elgamal()


if __name__ == "__main__":
    # Демонстрация Pedersen
    val = 42
    cmt, rand = pedersen_commit.commit(val)
    assert pedersen_commit.verify(cmt, val, rand)
    logger.info(f"Pedersen commitment passed: {cmt}")

    # Демонстрация ElGamal
    c1, c2, r2 = elgamal_commit.commit(val)
    assert elgamal_commit.verify(c1, c2, val, r2)
    logger.info(f"ElGamal commitment passed: {c1}, {c2}")
