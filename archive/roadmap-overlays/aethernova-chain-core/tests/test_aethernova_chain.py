"""
Comprehensive tests для aethernova-chain-core
Тестируем: Block mining, Transactions, Consensus, Smart contracts, Chain validation
"""

import pytest
import asyncio
from datetime import datetime
from typing import Dict, Any

from src.block import Block, Transaction, BlockValidator
from src.chain import Blockchain
from src.consensus import ConsensusEngine, ConsensusType
from src.smart_contracts import SmartContract, ContractVM, ContractManager


class TestBlockBasics:
    """Тесты основной функциональности блоков"""
    
    def test_transaction_creation(self):
        """Тест создания транзакции"""
        tx = Transaction(
            sender="alice",
            receiver="bob",
            amount=100.0,
            timestamp=datetime.now().timestamp(),
            data={"memo": "payment"}
        )
        
        assert tx.sender == "alice"
        assert tx.receiver == "bob"
        assert tx.amount == 100.0
        assert tx.data["memo"] == "payment"
    
    def test_transaction_hash(self):
        """Тест генерации хэша транзакции"""
        tx1 = Transaction(
            sender="alice",
            receiver="bob",
            amount=100.0,
            timestamp=1234567890.0,
            data=None
        )
        
        tx2 = Transaction(
            sender="alice",
            receiver="bob",
            amount=100.0,
            timestamp=1234567890.0,
            data=None
        )
        
        # Одинаковые транзакции должны иметь одинаковый хэш
        assert tx1.calculate_hash() == tx2.calculate_hash()
    
    def test_block_creation(self):
        """Тест создания блока"""
        transactions = [
            Transaction("alice", "bob", 50.0, datetime.now().timestamp(), None)
        ]
        
        block = Block(
            index=1,
            timestamp=datetime.now().timestamp(),
            transactions=transactions,
            previous_hash="0" * 64,
            nonce=0
        )
        
        assert block.index == 1
        assert len(block.transactions) == 1
        assert block.previous_hash == "0" * 64
    
    def test_block_hash_calculation(self):
        """Тест расчета хэша блока"""
        transactions = [
            Transaction("alice", "bob", 50.0, 1234567890.0, None)
        ]
        
        block1 = Block(1, 1234567890.0, transactions, "0" * 64, 0)
        block2 = Block(1, 1234567890.0, transactions, "0" * 64, 0)
        
        # Одинаковые блоки должны иметь одинаковый хэш
        assert block1.calculate_hash() == block2.calculate_hash()
    
    @pytest.mark.asyncio
    async def test_block_mining(self):
        """Тест майнинга блока"""
        transactions = [
            Transaction("alice", "bob", 50.0, datetime.now().timestamp(), None)
        ]
        
        block = Block(1, datetime.now().timestamp(), transactions, "0" * 64, 0)
        
        # Майним с небольшой сложностью для быстрого теста
        await block.mine_block(difficulty=2)
        
        # Проверяем что хэш начинается с нужного количества нулей
        assert block.hash.startswith("00")
        assert block.nonce > 0


class TestBlockchain:
    """Тесты блокчейна"""
    
    @pytest.mark.asyncio
    async def test_blockchain_creation(self):
        """Тест создания блокчейна"""
        blockchain = Blockchain(difficulty=2)
        
        assert len(blockchain.chain) == 1  # Genesis block
        assert blockchain.chain[0].index == 0
        assert blockchain.difficulty == 2
    
    @pytest.mark.asyncio
    async def test_add_transaction(self):
        """Тест добавления транзакции"""
        blockchain = Blockchain(difficulty=2)
        
        tx = Transaction("alice", "bob", 100.0, datetime.now().timestamp(), None)
        result = blockchain.add_transaction(tx)
        
        assert result is True
        assert len(blockchain.pending_transactions) == 1
    
    @pytest.mark.asyncio
    async def test_mine_pending_transactions(self):
        """Тест майнинга ожидающих транзакций"""
        blockchain = Blockchain(difficulty=2)
        
        # Добавляем транзакции
        blockchain.add_transaction(
            Transaction("alice", "bob", 50.0, datetime.now().timestamp(), None)
        )
        blockchain.add_transaction(
            Transaction("bob", "charlie", 25.0, datetime.now().timestamp(), None)
        )
        
        # Майним блок
        block = await blockchain.mine_pending_transactions("miner1")
        
        assert block is not None
        assert len(blockchain.chain) == 2  # Genesis + новый блок
        assert len(blockchain.pending_transactions) == 1  # Mining reward
        assert block.hash.startswith("00")
    
    @pytest.mark.asyncio
    async def test_chain_validation(self):
        """Тест валидации цепи"""
        blockchain = Blockchain(difficulty=2)
        
        # Добавляем и майним несколько блоков
        blockchain.add_transaction(
            Transaction("alice", "bob", 50.0, datetime.now().timestamp(), None)
        )
        await blockchain.mine_pending_transactions("miner1")
        
        blockchain.add_transaction(
            Transaction("bob", "charlie", 25.0, datetime.now().timestamp(), None)
        )
        await blockchain.mine_pending_transactions("miner1")
        
        # Цепь должна быть валидной
        assert blockchain.is_chain_valid() is True
    
    @pytest.mark.asyncio
    async def test_chain_tampering_detection(self):
        """Тест обнаружения подделки цепи"""
        blockchain = Blockchain(difficulty=2)
        
        # Создаем блок
        blockchain.add_transaction(
            Transaction("alice", "bob", 50.0, datetime.now().timestamp(), None)
        )
        await blockchain.mine_pending_transactions("miner1")
        
        # Подделываем данные в блоке
        blockchain.chain[1].transactions[0].amount = 1000.0
        
        # Цепь должна быть невалидной
        assert blockchain.is_chain_valid() is False
    
    @pytest.mark.asyncio
    async def test_get_balance(self):
        """Тест получения баланса"""
        blockchain = Blockchain(difficulty=2, mining_reward=10.0)
        
        # Начальные транзакции
        blockchain.add_transaction(
            Transaction("genesis", "alice", 100.0, datetime.now().timestamp(), None)
        )
        await blockchain.mine_pending_transactions("miner1")
        
        blockchain.add_transaction(
            Transaction("alice", "bob", 30.0, datetime.now().timestamp(), None)
        )
        await blockchain.mine_pending_transactions("miner1")
        
        # Проверяем балансы
        alice_balance = blockchain.get_balance("alice")
        bob_balance = blockchain.get_balance("bob")
        miner_balance = blockchain.get_balance("miner1")
        
        assert alice_balance == 70.0  # 100 - 30
        assert bob_balance == 30.0
        assert miner_balance == 20.0  # 2 блока * 10 reward
    
    @pytest.mark.asyncio
    async def test_transaction_history(self):
        """Тест получения истории транзакций"""
        blockchain = Blockchain(difficulty=2)
        
        blockchain.add_transaction(
            Transaction("alice", "bob", 50.0, datetime.now().timestamp(), None)
        )
        blockchain.add_transaction(
            Transaction("alice", "charlie", 25.0, datetime.now().timestamp(), None)
        )
        await blockchain.mine_pending_transactions("miner1")
        
        history = blockchain.get_transaction_history("alice")
        
        assert len(history) == 2
        assert history[0].receiver == "bob"
        assert history[1].receiver == "charlie"


class TestConsensus:
    """Тесты консенсуса"""
    
    def test_consensus_engine_creation(self):
        """Тест создания consensus engine"""
        engine = ConsensusEngine(ConsensusType.PROOF_OF_WORK, min_validators=3)
        
        assert engine.consensus_type == ConsensusType.PROOF_OF_WORK
        assert engine.min_validators == 3
    
    def test_add_validator(self):
        """Тест добавления валидатора"""
        engine = ConsensusEngine(ConsensusType.PROOF_OF_STAKE, min_validators=2)
        
        engine.add_validator("validator1", stake=1000.0)
        engine.add_validator("validator2", stake=2000.0)
        
        stats = engine.get_stats()
        assert stats["total_validators"] == 2
        assert stats["total_stake"] == 3000.0
    
    def test_remove_validator(self):
        """Тест удаления валидатора"""
        engine = ConsensusEngine(ConsensusType.PROOF_OF_STAKE, min_validators=1)
        
        engine.add_validator("validator1", stake=1000.0)
        engine.add_validator("validator2", stake=2000.0)
        
        result = engine.remove_validator("validator1")
        
        assert result is True
        stats = engine.get_stats()
        assert stats["total_validators"] == 1
    
    @pytest.mark.asyncio
    async def test_pow_validation(self):
        """Тест Proof of Work валидации"""
        engine = ConsensusEngine(ConsensusType.PROOF_OF_WORK, min_validators=1)
        engine.add_validator("miner1", stake=0)
        
        # Создаем блок с правильным PoW
        transactions = [
            Transaction("alice", "bob", 50.0, datetime.now().timestamp(), None)
        ]
        block = Block(1, datetime.now().timestamp(), transactions, "0" * 64, 0)
        await block.mine_block(difficulty=2)
        
        result = await engine.validate_block(block, "miner1", difficulty=2)
        assert result is True
    
    @pytest.mark.asyncio
    async def test_pos_validator_selection(self):
        """Тест выбора валидатора в Proof of Stake"""
        engine = ConsensusEngine(ConsensusType.PROOF_OF_STAKE, min_validators=2)
        
        engine.add_validator("validator1", stake=1000.0)
        engine.add_validator("validator2", stake=2000.0)
        engine.add_validator("validator3", stake=500.0)
        
        validator = engine.select_validator()
        
        # Валидатор должен быть выбран
        assert validator in ["validator1", "validator2", "validator3"]
        
        # Validator2 должен выбираться чаще из-за большего стейка
        selections = {}
        for _ in range(100):
            v = engine.select_validator()
            selections[v] = selections.get(v, 0) + 1
        
        # Validator2 должен иметь больше всего выборов
        assert selections["validator2"] > selections["validator1"]
        assert selections["validator2"] > selections["validator3"]


class TestSmartContracts:
    """Тесты смарт-контрактов"""
    
    @pytest.mark.asyncio
    async def test_contract_creation(self):
        """Тест создания контракта"""
        contract = SmartContract(
            contract_id="token_001",
            owner="alice",
            code="balance = 1000",
            created_at=datetime.now()
        )
        
        assert contract.contract_id == "token_001"
        assert contract.owner == "alice"
        assert contract.state == {}
    
    @pytest.mark.asyncio
    async def test_contract_vm_execution(self):
        """Тест выполнения кода в VM"""
        vm = ContractVM(gas_limit=10000)
        
        code = """
result = args['a'] + args['b']
"""
        
        result = await vm.execute(code, {"a": 10, "b": 20}, {}, "caller")
        
        assert result["success"] is True
        assert result["result"]["result"] == 30
        assert result["gas_used"] > 0
    
    @pytest.mark.asyncio
    async def test_contract_vm_gas_limit(self):
        """Тест ограничения газа"""
        vm = ContractVM(gas_limit=100)  # Очень маленький лимит
        
        # Бесконечный цикл должен превысить лимит газа
        code = """
while True:
    x = 1
"""
        
        result = await vm.execute(code, {}, {}, "caller")
        
        assert result["success"] is False
        assert "timeout" in result["error"].lower() or "gas" in result["error"].lower()
    
    @pytest.mark.asyncio
    async def test_contract_manager(self):
        """Тест менеджера контрактов"""
        manager = ContractManager()
        
        # Деплой контракта
        code = """
def init():
    state['balance'] = 1000
    state['owner'] = args['owner']

init()
"""
        
        await manager.deploy_contract("token_001", "alice", code)
        
        stats = manager.get_stats()
        assert stats["total_contracts"] == 1
    
    @pytest.mark.asyncio
    async def test_contract_function_call(self):
        """Тест вызова функции контракта"""
        manager = ContractManager()
        
        # Деплой контракта с функциями
        code = """
state['balance'] = 1000

def get_balance():
    return state['balance']

def transfer(amount):
    if state['balance'] >= amount:
        state['balance'] -= amount
        return True
    return False
"""
        
        await manager.deploy_contract("token_001", "alice", code)
        
        # Вызываем get_balance
        result = await manager.call_contract(
            "token_001",
            "get_balance",
            {},
            "alice"
        )
        
        assert result["success"] is True
        assert result["result"] == 1000
        
        # Вызываем transfer
        result = await manager.call_contract(
            "token_001",
            "transfer",
            {"amount": 300},
            "alice"
        )
        
        assert result["success"] is True
        assert result["result"] is True
        
        # Проверяем новый баланс
        result = await manager.call_contract(
            "token_001",
            "get_balance",
            {},
            "alice"
        )
        
        assert result["result"] == 700


class TestBlockValidator:
    """Тесты валидации блоков"""
    
    @pytest.mark.asyncio
    async def test_validate_block_structure(self):
        """Тест валидации структуры блока"""
        validator = BlockValidator()
        
        transactions = [
            Transaction("alice", "bob", 50.0, datetime.now().timestamp(), None)
        ]
        block = Block(1, datetime.now().timestamp(), transactions, "0" * 64, 0)
        await block.mine_block(difficulty=2)
        
        result = await validator.validate_block(block, "0" * 64, difficulty=2)
        
        assert result is True
    
    @pytest.mark.asyncio
    async def test_invalid_previous_hash(self):
        """Тест невалидного previous_hash"""
        validator = BlockValidator()
        
        transactions = [
            Transaction("alice", "bob", 50.0, datetime.now().timestamp(), None)
        ]
        block = Block(1, datetime.now().timestamp(), transactions, "wrong_hash", 0)
        await block.mine_block(difficulty=2)
        
        result = await validator.validate_block(block, "correct_hash", difficulty=2)
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_invalid_proof_of_work(self):
        """Тест невалидного Proof of Work"""
        validator = BlockValidator()
        
        transactions = [
            Transaction("alice", "bob", 50.0, datetime.now().timestamp(), None)
        ]
        block = Block(1, datetime.now().timestamp(), transactions, "0" * 64, 0)
        # Не майним блок, поэтому PoW будет невалидным
        
        result = await validator.validate_block(block, "0" * 64, difficulty=2)
        
        assert result is False


# Pytest fixtures
@pytest.fixture
def sample_blockchain():
    """Фикстура для тестового блокчейна"""
    return Blockchain(difficulty=2, mining_reward=10.0)


@pytest.fixture
def sample_consensus_engine():
    """Фикстура для consensus engine"""
    engine = ConsensusEngine(ConsensusType.PROOF_OF_WORK, min_validators=1)
    engine.add_validator("test_miner", stake=1000.0)
    return engine


@pytest.fixture
def sample_contract_manager():
    """Фикстура для contract manager"""
    return ContractManager()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
