import hashlib
from typing import List, Optional

# Pedersen Commitments and Poseidon are complex cryptographic primitives.
# Here — максимально упрощённая реализация для zk-среды, готовая для интеграции с настоящими библиотеками.

def sha256_hash(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def pedersen_commitment(value: int, blinding_factor: int) -> bytes:
    # Заглушка. Реальные Pedersen commitments работают над эллиптическими кривыми.
    # Здесь для примера — хэш от value и blinding_factor
    data = value.to_bytes(32, 'big') + blinding_factor.to_bytes(32, 'big')
    return sha256_hash(data)

def merkle_tree(leaves: List[bytes]) -> List[List[bytes]]:
    """
    Построение дерева Меркла.
    Возвращает список уровней дерева, начиная с листьев и заканчивая корнем.
    """
    tree = [leaves]
    while len(tree[-1]) > 1:
        current_level = tree[-1]
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i+1] if i+1 < len(current_level) else current_level[i]
            combined = sha256_hash(left + right)
            next_level.append(combined)
        tree.append(next_level)
    return tree

def merkle_root(leaves: List[bytes]) -> Optional[bytes]:
    if not leaves:
        return None
    tree = merkle_tree(leaves)
    return tree[-1][0]

def poseidon_hash(inputs: List[int]) -> int:
    """
    Заглушка Poseidon hash — это хэш функция, оптимизированная для zk-SNARK.
    Реализовать полноценно сложно, нужно использовать готовые библиотеки.
    Здесь просто возвращаем сумму по модулю большого простого числа.
    """
    MODULUS = 2**255 - 19
    return sum(inputs) % MODULUS

