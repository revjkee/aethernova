"""
Consensus Engine - AetherNova Chain Core
Механизм консенсуса для блокчейна
"""

import asyncio
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime
from enum import Enum
from loguru import logger

from .block import Block
from .chain import Blockchain


class ConsensusType(str, Enum):
    """Типы консенсуса"""
    PROOF_OF_WORK = "pow"
    PROOF_OF_STAKE = "pos"
    PROOF_OF_AUTHORITY = "poa"
    DELEGATED_POS = "dpos"


class ConsensusEngine:
    """Движок консенсуса"""
    
    def __init__(
        self,
        consensus_type: ConsensusType = ConsensusType.PROOF_OF_WORK,
        min_validators: int = 3
    ):
        self.consensus_type = consensus_type
        self.min_validators = min_validators
        self.validators: Dict[str, float] = {}  # address -> stake/reputation
        self.votes: Dict[str, List[str]] = {}  # block_hash -> [validator_addresses]
        
        logger.info(f"🔧 Consensus Engine инициализирован: {consensus_type}")
    
    async def validate_block(
        self,
        block: Block,
        blockchain: Blockchain
    ) -> bool:
        """
        Валидирует блок согласно механизму консенсуса
        
        Args:
            block: Блок для валидации
            blockchain: Текущий блокчейн
            
        Returns:
            True если блок валиден
        """
        if self.consensus_type == ConsensusType.PROOF_OF_WORK:
            return await self._validate_pow(block)
        elif self.consensus_type == ConsensusType.PROOF_OF_STAKE:
            return await self._validate_pos(block, blockchain)
        elif self.consensus_type == ConsensusType.PROOF_OF_AUTHORITY:
            return await self._validate_poa(block)
        elif self.consensus_type == ConsensusType.DELEGATED_POS:
            return await self._validate_dpos(block, blockchain)
        
        return False
    
    async def _validate_pow(self, block: Block) -> bool:
        """Валидация Proof of Work"""
        # Проверка хеша с нужным количеством нулей
        target = "0" * block.difficulty
        is_valid = block.hash.startswith(target)
        
        if is_valid:
            logger.debug(f"✅ PoW валидация пройдена: {block.hash[:16]}...")
        else:
            logger.warning(f"⚠️ PoW валидация провалена: {block.hash[:16]}...")
        
        return is_valid
    
    async def _validate_pos(self, block: Block, blockchain: Blockchain) -> bool:
        """Валидация Proof of Stake"""
        # Проверка что майнер имеет достаточный стейк
        if block.miner not in self.validators:
            logger.warning(f"⚠️ Майнер {block.miner} не является валидатором")
            return False
        
        stake = self.validators[block.miner]
        min_stake = 100.0  # Минимальный стейк
        
        if stake < min_stake:
            logger.warning(f"⚠️ Недостаточный стейк у {block.miner}: {stake} < {min_stake}")
            return False
        
        logger.debug(f"✅ PoS валидация пройдена для {block.miner}")
        return True
    
    async def _validate_poa(self, block: Block) -> bool:
        """Валидация Proof of Authority"""
        # Проверка что майнер является авторизованным валидатором
        if block.miner not in self.validators:
            logger.warning(f"⚠️ Майнер {block.miner} не авторизован")
            return False
        
        logger.debug(f"✅ PoA валидация пройдена для {block.miner}")
        return True
    
    async def _validate_dpos(self, block: Block, blockchain: Blockchain) -> bool:
        """Валидация Delegated Proof of Stake"""
        # Проверка что майнер является делегатом
        if block.miner not in self.validators:
            logger.warning(f"⚠️ Майнер {block.miner} не является делегатом")
            return False
        
        # Проверка голосов
        votes = self.validators[block.miner]
        min_votes = 1000.0  # Минимальное количество голосов
        
        if votes < min_votes:
            logger.warning(f"⚠️ Недостаточно голосов у {block.miner}: {votes} < {min_votes}")
            return False
        
        logger.debug(f"✅ DPoS валидация пройдена для {block.miner}")
        return True
    
    async def select_block_producer(
        self,
        candidates: List[str],
        blockchain: Blockchain
    ) -> Optional[str]:
        """
        Выбирает производителя следующего блока
        
        Args:
            candidates: Список кандидатов
            blockchain: Текущий блокчейн
            
        Returns:
            Адрес выбранного производителя
        """
        if self.consensus_type == ConsensusType.PROOF_OF_WORK:
            # В PoW любой может майнить
            return candidates[0] if candidates else None
        
        elif self.consensus_type == ConsensusType.PROOF_OF_STAKE:
            # В PoS выбираем пропорционально стейку
            return await self._select_by_stake(candidates)
        
        elif self.consensus_type == ConsensusType.PROOF_OF_AUTHORITY:
            # В PoA ротация по кругу
            return await self._select_by_rotation(candidates, blockchain)
        
        elif self.consensus_type == ConsensusType.DELEGATED_POS:
            # В DPoS выбираем из топ делегатов
            return await self._select_top_delegate(candidates)
        
        return None
    
    async def _select_by_stake(self, candidates: List[str]) -> Optional[str]:
        """Выбор пропорционально стейку"""
        import random
        
        # Фильтруем только валидаторов
        valid_candidates = [c for c in candidates if c in self.validators]
        
        if not valid_candidates:
            return None
        
        # Взвешенный случайный выбор
        total_stake = sum(self.validators[c] for c in valid_candidates)
        
        if total_stake == 0:
            return random.choice(valid_candidates)
        
        rand_value = random.uniform(0, total_stake)
        current_sum = 0
        
        for candidate in valid_candidates:
            current_sum += self.validators[candidate]
            if current_sum >= rand_value:
                return candidate
        
        return valid_candidates[-1]
    
    async def _select_by_rotation(
        self,
        candidates: List[str],
        blockchain: Blockchain
    ) -> Optional[str]:
        """Выбор по ротации"""
        valid_candidates = [c for c in candidates if c in self.validators]
        
        if not valid_candidates:
            return None
        
        # Ротация основана на высоте блока
        index = len(blockchain.chain) % len(valid_candidates)
        return valid_candidates[index]
    
    async def _select_top_delegate(self, candidates: List[str]) -> Optional[str]:
        """Выбор топ делегата"""
        valid_candidates = [c for c in candidates if c in self.validators]
        
        if not valid_candidates:
            return None
        
        # Сортируем по количеству голосов
        sorted_candidates = sorted(
            valid_candidates,
            key=lambda c: self.validators[c],
            reverse=True
        )
        
        return sorted_candidates[0]
    
    def add_validator(self, address: str, stake_or_votes: float = 0) -> bool:
        """Добавляет валидатора"""
        if address in self.validators:
            logger.warning(f"⚠️ Валидатор {address} уже существует")
            return False
        
        self.validators[address] = stake_or_votes
        logger.info(f"✅ Валидатор добавлен: {address} ({stake_or_votes})")
        return True
    
    def remove_validator(self, address: str) -> bool:
        """Удаляет валидатора"""
        if address not in self.validators:
            logger.warning(f"⚠️ Валидатор {address} не найден")
            return False
        
        del self.validators[address]
        logger.info(f"✅ Валидатор удалён: {address}")
        return True
    
    def update_stake(self, address: str, new_stake: float) -> bool:
        """Обновляет стейк/голоса валидатора"""
        if address not in self.validators:
            logger.warning(f"⚠️ Валидатор {address} не найден")
            return False
        
        old_stake = self.validators[address]
        self.validators[address] = new_stake
        logger.info(f"✅ Стейк обновлён: {address} ({old_stake} -> {new_stake})")
        return True
    
    async def vote_for_block(self, block_hash: str, validator_address: str) -> bool:
        """Голосование за блок"""
        if validator_address not in self.validators:
            logger.warning(f"⚠️ {validator_address} не является валидатором")
            return False
        
        if block_hash not in self.votes:
            self.votes[block_hash] = []
        
        if validator_address in self.votes[block_hash]:
            logger.warning(f"⚠️ {validator_address} уже проголосовал за блок")
            return False
        
        self.votes[block_hash].append(validator_address)
        logger.debug(f"✅ Голос от {validator_address} за блок {block_hash[:16]}...")
        return True
    
    async def has_consensus(self, block_hash: str) -> bool:
        """Проверяет достигнут ли консенсус для блока"""
        if block_hash not in self.votes:
            return False
        
        votes_count = len(self.votes[block_hash])
        total_validators = len(self.validators)
        
        # Требуем 2/3+ голосов
        required_votes = (total_validators * 2 // 3) + 1
        
        has_consensus = votes_count >= required_votes
        
        if has_consensus:
            logger.info(f"✅ Консенсус достигнут для блока {block_hash[:16]}... ({votes_count}/{total_validators})")
        
        return has_consensus
    
    def get_stats(self) -> Dict[str, Any]:
        """Возвращает статистику консенсуса"""
        return {
            "consensus_type": self.consensus_type.value,
            "total_validators": len(self.validators),
            "min_validators": self.min_validators,
            "validators": dict(self.validators),
            "pending_votes": len(self.votes)
        }
