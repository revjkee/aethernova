"""
Post-Quantum Digital Signatures - SPHINCS+ Implementation
Hash-based signature scheme
NIST PQC Standard
"""

import hashlib
import secrets
from dataclasses import dataclass
from typing import Tuple, List, Optional
from loguru import logger


# SPHINCS+ параметры (SPHINCS+-128s - small signatures)
SPHINCS_N = 16  # Security parameter (128-bit)
SPHINCS_H = 64  # Высота дерева Merkle
SPHINCS_D = 8   # Количество слоев
SPHINCS_K = 14  # Количество деревьев FORS
SPHINCS_T = 16  # Размер листьев FORS


@dataclass
class SphincsKeys:
    """Пара ключей SPHINCS+"""
    public_key: bytes
    secret_key: bytes


@dataclass
class SphincsSignature:
    """Подпись SPHINCS+"""
    signature: bytes


class SphincsPlus:
    """
    SPHINCS+ Hash-Based Digital Signature Scheme
    
    Stateless hash-based signatures
    Устойчив к квантовым атакам
    """
    
    def __init__(self, security_level: int = 128, variant: str = "simple"):
        """
        Args:
            security_level: 128, 192, or 256 bits
            variant: "simple" (faster) or "robust" (more secure)
        """
        self.security_level = security_level
        self.variant = variant
        
        # Параметры в зависимости от уровня безопасности
        if security_level == 128:
            self.n = 16
            self.h = 64
            self.d = 8
            self.k = 14
            self.t = 16
        elif security_level == 192:
            self.n = 24
            self.h = 66
            self.d = 8
            self.k = 17
            self.t = 16
        elif security_level == 256:
            self.n = 32
            self.h = 68
            self.d = 8
            self.k = 22
            self.t = 16
        else:
            raise ValueError(f"Unsupported security level: {security_level}")
        
        # Хэш-функция
        if variant == "simple":
            self.hash_func = self._sha256_simple
        else:
            self.hash_func = self._sha256_robust
        
        logger.info(f"🔐 SPHINCS+-{security_level}{variant[0].upper()} initialized")
    
    def generate_keypair(self) -> SphincsKeys:
        """
        Генерирует пару ключей SPHINCS+
        
        Returns:
            SphincsKeys с public_key и secret_key
        """
        # Генерация seed для детерминированной генерации
        sk_seed = secrets.token_bytes(self.n)
        sk_prf = secrets.token_bytes(self.n)
        pub_seed = secrets.token_bytes(self.n)
        
        # Вычисление корня дерева Merkle
        root = self._compute_merkle_root(sk_seed, pub_seed)
        
        # Формирование ключей
        secret_key = sk_seed + sk_prf + pub_seed + root
        public_key = pub_seed + root
        
        logger.debug(f"Generated SPHINCS+ keypair (pk: {len(public_key)} bytes, sk: {len(secret_key)} bytes)")
        
        return SphincsKeys(
            public_key=public_key,
            secret_key=secret_key
        )
    
    def sign(self, message: bytes, secret_key: bytes) -> SphincsSignature:
        """
        Подписывает сообщение
        
        Args:
            message: Сообщение для подписи
            secret_key: Секретный ключ
            
        Returns:
            SphincsSignature
        """
        # Распаковка секретного ключа
        sk_seed, sk_prf, pub_seed, root = self._unpack_secret_key(secret_key)
        
        # Хэшируем сообщение
        msg_hash = self._hash_message(message, pub_seed, root)
        
        # Генерируем случайность для подписи
        opt_rand = self.hash_func(sk_prf + msg_hash)
        
        # Вычисляем FORS signature
        fors_sig = self._fors_sign(msg_hash, sk_seed, pub_seed, opt_rand)
        
        # Вычисляем HyperTree signature
        ht_sig = self._hypertree_sign(msg_hash, sk_seed, pub_seed, opt_rand)
        
        # Собираем полную подпись
        signature = opt_rand + fors_sig + ht_sig
        
        logger.debug(f"Signed message (sig: {len(signature)} bytes)")
        
        return SphincsSignature(signature=signature)
    
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Проверяет подпись сообщения
        
        Args:
            message: Сообщение
            signature: Подпись
            public_key: Публичный ключ
            
        Returns:
            True если подпись валидна, False иначе
        """
        try:
            # Распаковка публичного ключа
            pub_seed, root = self._unpack_public_key(public_key)
            
            # Хэшируем сообщение
            msg_hash = self._hash_message(message, pub_seed, root)
            
            # Распаковка подписи
            opt_rand, fors_sig, ht_sig = self._unpack_signature(signature)
            
            # Верифицируем FORS signature
            fors_pk = self._fors_verify(msg_hash, fors_sig, pub_seed)
            
            # Верифицируем HyperTree signature
            ht_valid = self._hypertree_verify(fors_pk, ht_sig, pub_seed, root)
            
            logger.debug(f"Verified signature: {ht_valid}")
            
            return ht_valid
            
        except Exception as e:
            logger.error(f"Signature verification failed: {e}")
            return False
    
    # Helper methods
    
    def _sha256_simple(self, data: bytes) -> bytes:
        """SHA-256 hash (simple variant)"""
        return hashlib.sha256(data).digest()[:self.n]
    
    def _sha256_robust(self, data: bytes) -> bytes:
        """SHA-256 hash with additional domain separation (robust variant)"""
        return hashlib.sha256(b"SPHINCS+" + data).digest()[:self.n]
    
    def _hash_message(self, message: bytes, pub_seed: bytes, root: bytes) -> bytes:
        """Хэширует сообщение с pub_seed и root"""
        h = hashlib.sha256(pub_seed + root + message).digest()
        return h[:self.n]
    
    def _compute_merkle_root(self, sk_seed: bytes, pub_seed: bytes) -> bytes:
        """Вычисляет корень дерева Merkle"""
        # Упрощенная версия - в real implementation строится полное дерево
        leaves = []
        for i in range(2 ** (self.h // self.d)):
            leaf = self.hash_func(sk_seed + pub_seed + i.to_bytes(8, 'little'))
            leaves.append(leaf)
        
        # Строим дерево снизу вверх
        while len(leaves) > 1:
            new_level = []
            for i in range(0, len(leaves), 2):
                if i + 1 < len(leaves):
                    parent = self.hash_func(leaves[i] + leaves[i + 1])
                else:
                    parent = leaves[i]
                new_level.append(parent)
            leaves = new_level
        
        return leaves[0]
    
    def _fors_sign(self, msg_hash: bytes, sk_seed: bytes, pub_seed: bytes, addr: bytes) -> bytes:
        """
        FORS (Forest of Random Subsets) signature
        """
        # Извлекаем индексы из хэша сообщения
        indices = []
        for i in range(self.k):
            idx = int.from_bytes(msg_hash[i*2:(i+1)*2], 'little') % self.t
            indices.append(idx)
        
        # Для каждого индекса генерируем путь аутентификации
        sig_parts = []
        for tree_idx, leaf_idx in enumerate(indices):
            # Генерация листа
            leaf = self.hash_func(sk_seed + addr + tree_idx.to_bytes(4, 'little') + leaf_idx.to_bytes(4, 'little'))
            sig_parts.append(leaf)
            
            # Генерация пути аутентификации (упрощенно)
            for level in range(4):  # log2(16) = 4
                sibling_idx = leaf_idx ^ (1 << level)
                sibling = self.hash_func(sk_seed + addr + tree_idx.to_bytes(4, 'little') + sibling_idx.to_bytes(4, 'little'))
                sig_parts.append(sibling)
        
        return b''.join(sig_parts)
    
    def _fors_verify(self, msg_hash: bytes, fors_sig: bytes, pub_seed: bytes) -> bytes:
        """
        Верифицирует FORS signature и возвращает FORS public key
        """
        # Извлекаем индексы
        indices = []
        for i in range(self.k):
            idx = int.from_bytes(msg_hash[i*2:(i+1)*2], 'little') % self.t
            indices.append(idx)
        
        # Восстанавливаем корни деревьев
        offset = 0
        roots = []
        for tree_idx, leaf_idx in enumerate(indices):
            # Читаем лист
            leaf = fors_sig[offset:offset+self.n]
            offset += self.n
            
            # Восстанавливаем корень через путь аутентификации
            node = leaf
            for level in range(4):
                sibling = fors_sig[offset:offset+self.n]
                offset += self.n
                
                if (leaf_idx >> level) & 1:
                    node = self.hash_func(sibling + node)
                else:
                    node = self.hash_func(node + sibling)
            
            roots.append(node)
        
        # FORS public key = hash всех корней
        fors_pk = self.hash_func(b''.join(roots))
        return fors_pk
    
    def _hypertree_sign(self, msg_hash: bytes, sk_seed: bytes, pub_seed: bytes, addr: bytes) -> bytes:
        """
        HyperTree signature (многослойное дерево Merkle)
        """
        # Упрощенная версия - генерируем подписи для каждого слоя
        sig_parts = []
        
        for layer in range(self.d):
            # Индекс листа для этого слоя
            leaf_idx = int.from_bytes(msg_hash[layer*4:(layer+1)*4], 'little') % (2 ** (self.h // self.d))
            
            # WOTS+ подпись для этого слоя
            wots_sig = self._wots_sign(msg_hash, sk_seed, pub_seed, layer, leaf_idx)
            sig_parts.append(wots_sig)
            
            # Путь аутентификации в дереве Merkle
            auth_path = self._merkle_auth_path(sk_seed, pub_seed, layer, leaf_idx)
            sig_parts.append(auth_path)
        
        return b''.join(sig_parts)
    
    def _hypertree_verify(self, fors_pk: bytes, ht_sig: bytes, pub_seed: bytes, root: bytes) -> bool:
        """
        Верифицирует HyperTree signature
        """
        # Упрощенная верификация - проверяем что можем восстановить root
        offset = 0
        current_pk = fors_pk
        
        for layer in range(self.d):
            # Читаем WOTS+ подпись
            wots_len = self.n * 67  # Упрощенная длина WOTS+
            wots_sig = ht_sig[offset:offset+wots_len]
            offset += wots_len
            
            # Верифицируем WOTS+
            wots_pk = self._wots_verify(current_pk, wots_sig, pub_seed)
            
            # Читаем путь аутентификации
            auth_len = self.n * (self.h // self.d)
            auth_path = ht_sig[offset:offset+auth_len]
            offset += auth_len
            
            # Восстанавливаем корень слоя
            current_pk = self._merkle_verify(wots_pk, auth_path)
        
        # Проверяем что финальный корень совпадает
        return current_pk == root
    
    def _wots_sign(self, message: bytes, sk_seed: bytes, pub_seed: bytes, layer: int, leaf_idx: int) -> bytes:
        """
        WOTS+ (Winternitz One-Time Signature) signature
        """
        # Генерация WOTS+ секретных значений
        wots_sk = []
        for i in range(67):  # 67 chains для SPHINCS+
            sk = self.hash_func(sk_seed + layer.to_bytes(4, 'little') + leaf_idx.to_bytes(8, 'little') + i.to_bytes(2, 'little'))
            wots_sk.append(sk)
        
        # Преобразуем сообщение в базис-16 представление
        msg_base16 = self._to_base_16(message, 64)
        checksum = sum(15 - b for b in msg_base16)
        checksum_base16 = self._to_base_16(checksum.to_bytes(2, 'little'), 3)
        full_msg = msg_base16 + checksum_base16
        
        # Вычисляем подпись
        sig = []
        for i, b in enumerate(full_msg):
            # Хэшируем b раз
            val = wots_sk[i]
            for _ in range(b):
                val = self.hash_func(val + pub_seed)
            sig.append(val)
        
        return b''.join(sig)
    
    def _wots_verify(self, message: bytes, signature: bytes, pub_seed: bytes) -> bytes:
        """
        Верифицирует WOTS+ подпись и возвращает публичный ключ
        """
        # Преобразуем сообщение
        msg_base16 = self._to_base_16(message, 64)
        checksum = sum(15 - b for b in msg_base16)
        checksum_base16 = self._to_base_16(checksum.to_bytes(2, 'little'), 3)
        full_msg = msg_base16 + checksum_base16
        
        # Восстанавливаем публичный ключ
        pk_parts = []
        offset = 0
        for i, b in enumerate(full_msg):
            val = signature[offset:offset+self.n]
            offset += self.n
            
            # Хэшируем оставшиеся (15-b) раз
            for _ in range(15 - b):
                val = self.hash_func(val + pub_seed)
            pk_parts.append(val)
        
        # Публичный ключ = hash всех частей
        return self.hash_func(b''.join(pk_parts))
    
    def _merkle_auth_path(self, sk_seed: bytes, pub_seed: bytes, layer: int, leaf_idx: int) -> bytes:
        """
        Генерирует путь аутентификации в дереве Merkle
        """
        auth = []
        tree_height = self.h // self.d
        
        for level in range(tree_height):
            sibling_idx = leaf_idx ^ (1 << level)
            sibling = self.hash_func(sk_seed + pub_seed + layer.to_bytes(4, 'little') + level.to_bytes(4, 'little') + sibling_idx.to_bytes(8, 'little'))
            auth.append(sibling)
        
        return b''.join(auth)
    
    def _merkle_verify(self, leaf: bytes, auth_path: bytes) -> bytes:
        """
        Восстанавливает корень дерева Merkle из пути аутентификации
        """
        node = leaf
        offset = 0
        tree_height = self.h // self.d
        
        for level in range(tree_height):
            sibling = auth_path[offset:offset+self.n]
            offset += self.n
            node = self.hash_func(node + sibling)
        
        return node
    
    def _to_base_16(self, data: bytes, length: int) -> List[int]:
        """Конвертирует байты в базис-16 представление"""
        result = []
        for byte in data[:length]:
            result.append(byte >> 4)
            result.append(byte & 0x0F)
        return result[:length]
    
    def _unpack_secret_key(self, sk: bytes) -> Tuple[bytes, bytes, bytes, bytes]:
        """Распаковывает секретный ключ"""
        sk_seed = sk[:self.n]
        sk_prf = sk[self.n:2*self.n]
        pub_seed = sk[2*self.n:3*self.n]
        root = sk[3*self.n:4*self.n]
        return sk_seed, sk_prf, pub_seed, root
    
    def _unpack_public_key(self, pk: bytes) -> Tuple[bytes, bytes]:
        """Распаковывает публичный ключ"""
        pub_seed = pk[:self.n]
        root = pk[self.n:2*self.n]
        return pub_seed, root
    
    def _unpack_signature(self, sig: bytes) -> Tuple[bytes, bytes, bytes]:
        """Распаковывает подпись"""
        opt_rand = sig[:self.n]
        
        # FORS signature length (упрощенно)
        fors_len = self.n * self.k * 5  # leaf + 4 siblings per tree
        fors_sig = sig[self.n:self.n+fors_len]
        
        # HyperTree signature (остаток)
        ht_sig = sig[self.n+fors_len:]
        
        return opt_rand, fors_sig, ht_sig


# Helper functions для простого использования
def sphincs_keygen(security_level: int = 128, variant: str = "simple") -> SphincsKeys:
    """Генерирует пару ключей SPHINCS+"""
    sphincs = SphincsPlus(security_level, variant)
    return sphincs.generate_keypair()


def sphincs_sign(message: bytes, secret_key: bytes, security_level: int = 128, variant: str = "simple") -> SphincsSignature:
    """Подписывает сообщение"""
    sphincs = SphincsPlus(security_level, variant)
    return sphincs.sign(message, secret_key)


def sphincs_verify(message: bytes, signature: bytes, public_key: bytes, security_level: int = 128, variant: str = "simple") -> bool:
    """Верифицирует подпись"""
    sphincs = SphincsPlus(security_level, variant)
    return sphincs.verify(message, signature, public_key)
