"""
Blockchain Chain Management - AetherNova Chain Core
Управление цепочкой блоков
"""

import asyncio
import json
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path
from loguru import logger

from .block import Block, Transaction, BlockValidator


class Blockchain:
    """Класс управления блокчейном"""
    
    def __init__(self, difficulty: int = 4):
        self.chain: List[Block] = []
        self.pending_transactions: List[Transaction] = []
        self.difficulty = difficulty
        self.mining_reward = 10.0
        self.validator = BlockValidator(min_difficulty=2, max_difficulty=10)
        
        # Создание генезис блока
        if not self.chain:
            genesis = Block.create_genesis_block()
            self.chain.append(genesis)
            logger.info("⛓️ Генезис блок создан")
    
    def get_latest_block(self) -> Block:
        """Возвращает последний блок в цепи"""
        return self.chain[-1]
    
    def add_transaction(self, transaction: Transaction) -> bool:
        """
        Добавляет транзакцию в пул ожидающих
        
        Args:
            transaction: Транзакция для добавления
            
        Returns:
            True если транзакция добавлена
        """
        # Валидация транзакции
        if not self.validator.validate_transaction(transaction):
            logger.warning(f"⚠️ Невалидная транзакция: {transaction.tx_hash}")
            return False
        
        self.pending_transactions.append(transaction)
        logger.debug(f"✅ Транзакция добавлена: {transaction.tx_hash[:16]}...")
        return True
    
    async def mine_pending_transactions(self, miner_address: str) -> Optional[Block]:
        """
        Майнит ожидающие транзакции
        
        Args:
            miner_address: Адрес майнера
            
        Returns:
            Созданный блок или None
        """
        if not self.pending_transactions:
            logger.warning("⚠️ Нет транзакций для майнинга")
            return None
        
        # Добавляем награду майнеру
        reward_tx = Transaction(
            sender="SYSTEM",
            receiver=miner_address,
            amount=self.mining_reward,
            timestamp=datetime.now().timestamp(),
            data={"type": "mining_reward"}
        )
        self.pending_transactions.append(reward_tx)
        
        # Создаём новый блок
        new_block = Block(
            index=len(self.chain),
            timestamp=datetime.now().timestamp(),
            transactions=self.pending_transactions.copy(),
            previous_hash=self.get_latest_block().hash,
            miner=miner_address,
            difficulty=self.difficulty
        )
        
        logger.info(f"⛏️ Начало майнинга блока #{new_block.index}...")
        
        # Майним блок (асинхронно)
        await asyncio.to_thread(new_block.mine_block, self.difficulty)
        
        logger.info(f"✅ Блок #{new_block.index} успешно намайнен: {new_block.hash[:16]}...")
        
        # Добавляем блок в цепь
        self.chain.append(new_block)
        
        # Очищаем пул транзакций
        self.pending_transactions = []
        
        # Корректируем сложность
        self.difficulty = self.validator.adjust_difficulty(self.chain)
        
        return new_block
    
    def is_chain_valid(self) -> bool:
        """Проверяет валидность всей цепи"""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            
            # Валидация блока
            if not self.validator.validate_block(current_block, previous_block):
                logger.error(f"❌ Невалидный блок #{i}")
                return False
        
        logger.info("✅ Цепочка валидна")
        return True
    
    def get_balance(self, address: str) -> float:
        """
        Получает баланс адреса
        
        Args:
            address: Адрес для проверки
            
        Returns:
            Баланс адреса
        """
        balance = 0.0
        
        for block in self.chain:
            for tx in block.transactions:
                if tx.sender == address:
                    balance -= tx.amount
                if tx.receiver == address:
                    balance += tx.amount
        
        # Учитываем ожидающие транзакции
        for tx in self.pending_transactions:
            if tx.sender == address:
                balance -= tx.amount
        
        return balance
    
    def get_transaction_history(self, address: str) -> List[Transaction]:
        """Возвращает историю транзакций адреса"""
        history = []
        
        for block in self.chain:
            for tx in block.transactions:
                if tx.sender == address or tx.receiver == address:
                    history.append(tx)
        
        return history
    
    def get_block_by_index(self, index: int) -> Optional[Block]:
        """Получает блок по индексу"""
        if 0 <= index < len(self.chain):
            return self.chain[index]
        return None
    
    def get_block_by_hash(self, block_hash: str) -> Optional[Block]:
        """Получает блок по хешу"""
        for block in self.chain:
            if block.hash == block_hash:
                return block
        return None
    
    def get_transaction_by_hash(self, tx_hash: str) -> Optional[Transaction]:
        """Получает транзакцию по хешу"""
        for block in self.chain:
            for tx in block.transactions:
                if tx.tx_hash == tx_hash:
                    return tx
        return None
    
    def get_chain_stats(self) -> Dict[str, Any]:
        """Возвращает статистику цепи"""
        total_transactions = sum(len(block.transactions) for block in self.chain)
        
        return {
            "height": len(self.chain),
            "total_transactions": total_transactions,
            "pending_transactions": len(self.pending_transactions),
            "difficulty": self.difficulty,
            "mining_reward": self.mining_reward,
            "latest_block_hash": self.get_latest_block().hash,
            "latest_block_time": self.get_latest_block().timestamp
        }
    
    async def save_to_file(self, filepath: str) -> bool:
        """Сохраняет цепь в файл"""
        try:
            chain_data = {
                "chain": [block.to_dict() for block in self.chain],
                "pending_transactions": [tx.to_dict() for tx in self.pending_transactions],
                "difficulty": self.difficulty,
                "mining_reward": self.mining_reward
            }
            
            path = Path(filepath)
            path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(path, 'w') as f:
                json.dump(chain_data, f, indent=2)
            
            logger.info(f"💾 Цепь сохранена в {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Ошибка сохранения цепи: {e}")
            return False
    
    @classmethod
    async def load_from_file(cls, filepath: str) -> Optional['Blockchain']:
        """Загружает цепь из файла"""
        try:
            with open(filepath, 'r') as f:
                chain_data = json.load(f)
            
            blockchain = cls(difficulty=chain_data.get('difficulty', 4))
            blockchain.chain = [Block.from_dict(b) for b in chain_data['chain']]
            blockchain.pending_transactions = [
                Transaction.from_dict(tx) for tx in chain_data.get('pending_transactions', [])
            ]
            blockchain.mining_reward = chain_data.get('mining_reward', 10.0)
            
            # Валидация загруженной цепи
            if blockchain.is_chain_valid():
                logger.info(f"📂 Цепь загружена из {filepath}")
                return blockchain
            else:
                logger.error(f"❌ Загруженная цепь невалидна")
                return None
                
        except FileNotFoundError:
            logger.warning(f"⚠️ Файл {filepath} не найден, создаётся новая цепь")
            return cls()
        except Exception as e:
            logger.error(f"❌ Ошибка загрузки цепи: {e}")
            return None
    
    def fork_chain(self, from_index: int) -> Optional['Blockchain']:
        """
        Создаёт форк цепи с указанного блока
        
        Args:
            from_index: Индекс блока для форка
            
        Returns:
            Новая цепь или None
        """
        if from_index < 0 or from_index >= len(self.chain):
            return None
        
        forked = Blockchain(difficulty=self.difficulty)
        forked.chain = self.chain[:from_index + 1].copy()
        forked.mining_reward = self.mining_reward
        
        logger.info(f"🔱 Создан форк цепи с блока #{from_index}")
        return forked
    
    def replace_chain(self, new_chain: List[Block]) -> bool:
        """
        Заменяет текущую цепь новой (если она длиннее и валидна)
        
        Args:
            new_chain: Новая цепь блоков
            
        Returns:
            True если цепь заменена
        """
        if len(new_chain) <= len(self.chain):
            logger.info("⚠️ Новая цепь не длиннее текущей")
            return False
        
        # Создаём временную цепь для валидации
        temp_blockchain = Blockchain(difficulty=self.difficulty)
        temp_blockchain.chain = new_chain
        
        if not temp_blockchain.is_chain_valid():
            logger.error("❌ Новая цепь невалидна")
            return False
        
        # Заменяем цепь
        self.chain = new_chain
        logger.info(f"✅ Цепь заменена. Новая длина: {len(self.chain)}")
        return True
