"""
Block Structure - AetherNova Chain Core
Структура блока блокчейна
"""

import hashlib
import json
from typing import List, Dict, Any, Optional
from datetime import datetime
from dataclasses import dataclass, asdict


@dataclass
class Transaction:
    """Транзакция в блокчейне"""
    sender: str
    receiver: str
    amount: float
    timestamp: float
    signature: Optional[str] = None
    data: Optional[Dict[str, Any]] = None
    tx_hash: Optional[str] = None
    
    def __post_init__(self):
        """Генерация хеша транзакции"""
        if not self.tx_hash:
            self.tx_hash = self.calculate_hash()
    
    def calculate_hash(self) -> str:
        """Вычисляет хеш транзакции"""
        tx_data = {
            "sender": self.sender,
            "receiver": self.receiver,
            "amount": self.amount,
            "timestamp": self.timestamp,
            "data": self.data
        }
        tx_string = json.dumps(tx_data, sort_keys=True)
        return hashlib.sha256(tx_string.encode()).hexdigest()
    
    def to_dict(self) -> Dict[str, Any]:
        """Преобразует транзакцию в словарь"""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Transaction':
        """Создаёт транзакцию из словаря"""
        return cls(**data)


@dataclass
class Block:
    """Блок блокчейна"""
    index: int
    timestamp: float
    transactions: List[Transaction]
    previous_hash: str
    nonce: int = 0
    hash: Optional[str] = None
    miner: Optional[str] = None
    difficulty: int = 4
    
    def __post_init__(self):
        """Генерация хеша блока"""
        if not self.hash:
            self.hash = self.calculate_hash()
    
    def calculate_hash(self) -> str:
        """Вычисляет хеш блока"""
        block_data = {
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": [tx.to_dict() for tx in self.transactions],
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "miner": self.miner
        }
        block_string = json.dumps(block_data, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()
    
    def mine_block(self, difficulty: int = None) -> None:
        """
        Майнинг блока (Proof of Work)
        
        Args:
            difficulty: Сложность майнинга (количество нулей в начале хеша)
        """
        if difficulty is not None:
            self.difficulty = difficulty
        
        target = "0" * self.difficulty
        
        while not self.hash.startswith(target):
            self.nonce += 1
            self.hash = self.calculate_hash()
    
    def is_valid(self, previous_block: Optional['Block'] = None) -> bool:
        """
        Проверяет валидность блока
        
        Args:
            previous_block: Предыдущий блок для проверки цепочки
            
        Returns:
            True если блок валидный
        """
        # Проверка хеша
        if self.hash != self.calculate_hash():
            return False
        
        # Проверка сложности
        target = "0" * self.difficulty
        if not self.hash.startswith(target):
            return False
        
        # Проверка связи с предыдущим блоком
        if previous_block:
            if self.previous_hash != previous_block.hash:
                return False
            if self.index != previous_block.index + 1:
                return False
        
        # Проверка транзакций
        for tx in self.transactions:
            if tx.tx_hash != tx.calculate_hash():
                return False
        
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """Преобразует блок в словарь"""
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": [tx.to_dict() for tx in self.transactions],
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "hash": self.hash,
            "miner": self.miner,
            "difficulty": self.difficulty
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Block':
        """Создаёт блок из словаря"""
        transactions = [Transaction.from_dict(tx) for tx in data['transactions']]
        return cls(
            index=data['index'],
            timestamp=data['timestamp'],
            transactions=transactions,
            previous_hash=data['previous_hash'],
            nonce=data.get('nonce', 0),
            hash=data.get('hash'),
            miner=data.get('miner'),
            difficulty=data.get('difficulty', 4)
        )
    
    @classmethod
    def create_genesis_block(cls) -> 'Block':
        """Создаёт генезис блок (первый блок в цепи)"""
        genesis_tx = Transaction(
            sender="GENESIS",
            receiver="GENESIS",
            amount=0,
            timestamp=datetime.now().timestamp(),
            data={"type": "genesis", "message": "AetherNova Genesis Block"}
        )
        
        genesis_block = cls(
            index=0,
            timestamp=datetime.now().timestamp(),
            transactions=[genesis_tx],
            previous_hash="0" * 64,
            nonce=0,
            miner="GENESIS",
            difficulty=4
        )
        
        genesis_block.mine_block()
        return genesis_block


class BlockValidator:
    """Валидатор блоков"""
    
    def __init__(self, min_difficulty: int = 4, max_difficulty: int = 10):
        self.min_difficulty = min_difficulty
        self.max_difficulty = max_difficulty
    
    def validate_block(self, block: Block, previous_block: Optional[Block] = None) -> bool:
        """Валидирует блок"""
        return block.is_valid(previous_block)
    
    def validate_transaction(self, transaction: Transaction) -> bool:
        """Валидирует транзакцию"""
        # Проверка хеша
        if transaction.tx_hash != transaction.calculate_hash():
            return False
        
        # Проверка суммы
        if transaction.amount < 0:
            return False
        
        # Проверка адресов
        if not transaction.sender or not transaction.receiver:
            return False
        
        return True
    
    def adjust_difficulty(self, blocks: List[Block], target_time: int = 600) -> int:
        """
        Корректирует сложность майнинга на основе времени генерации блоков
        
        Args:
            blocks: Список последних блоков
            target_time: Целевое время генерации блока (секунды)
            
        Returns:
            Новая сложность
        """
        if len(blocks) < 2:
            return self.min_difficulty
        
        # Берём последние блоки для анализа
        recent_blocks = blocks[-10:] if len(blocks) >= 10 else blocks
        
        if len(recent_blocks) < 2:
            return self.min_difficulty
        
        # Вычисляем среднее время генерации
        time_diff = recent_blocks[-1].timestamp - recent_blocks[0].timestamp
        avg_time = time_diff / (len(recent_blocks) - 1)
        
        current_difficulty = recent_blocks[-1].difficulty
        
        # Корректируем сложность
        if avg_time < target_time * 0.5:
            # Слишком быстро - увеличиваем сложность
            new_difficulty = min(current_difficulty + 1, self.max_difficulty)
        elif avg_time > target_time * 2:
            # Слишком медленно - уменьшаем сложность
            new_difficulty = max(current_difficulty - 1, self.min_difficulty)
        else:
            # Нормально - оставляем как есть
            new_difficulty = current_difficulty
        
        return new_difficulty
