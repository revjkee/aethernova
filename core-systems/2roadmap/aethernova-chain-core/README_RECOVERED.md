# AetherNova Chain Core - ВОССТАНОВЛЕНО ⛓️

**Статус**: 🟢 EMERGENCY OPERATIONAL  
**Категория**: Blockchain Foundation  
**Приоритет**: 9/10 (Critical)

## 📋 Обзор

Основная блокчейн инфраструктура и децентрализованные операции для экосистемы AetherNova. Обеспечивает надежный blockchain с консенсусом, обработкой транзакций и выполнением смарт-контрактов.

## 🚀 Возможности

### Blockchain Core
- **Proof of Work консенсус** с настраиваемой сложностью
- **Transaction processing** с валидацией и подписями
- **Chain persistence** - сохранение и загрузка цепи
- **Genesis block** автоматическое создание
- **Balance tracking** - отслеживание балансов адресов
- **Transaction history** - полная история транзакций

### Consensus Engine
- **Multi-algorithm support**:
  - Proof of Work (PoW)
  - Proof of Stake (PoS)
  - Proof of Authority (PoA)
  - Delegated Proof of Stake (DPoS)
- **Validator management** - добавление/удаление валидаторов
- **Stake-based selection** для PoS
- **Block validation** с проверкой PoW

### Smart Contracts
- **Contract VM** с изоляцией выполнения
- **Gas metering** - ограничение ресурсов
- **State management** - персистентное хранилище состояния
- **Function calls** - вызов функций контрактов
- **Security sandbox** - безопасное выполнение кода

### Block Structure
- **SHA-256 hashing** для блоков и транзакций
- **Nonce-based mining** для Proof of Work
- **Transaction batching** в блоках
- **Chain linking** через previous_hash

## 📦 Компоненты

```
aethernova-chain-core/
├── src/
│   ├── block.py             # Block, Transaction, BlockValidator
│   ├── chain.py             # Blockchain management
│   ├── consensus.py         # ConsensusEngine with multi-algorithm
│   ├── smart_contracts.py   # SmartContract, ContractVM, ContractManager
│   └── __init__.py          # Exports
├── tests/
│   └── test_aethernova_chain.py  # 25 comprehensive tests
├── main.py                  # Main system class
├── config.py                # Configuration
└── requirements.txt         # Dependencies
```

## 🔧 Installation

```bash
cd /workspaces/aethernova/core-systems/aethernova-chain-core
pip install -r requirements.txt
```

## 💻 Использование

### Базовый запуск

```python
import asyncio
from main import AethernovaChainCore

async def main():
    # Создание экземпляра
    chain_core = AethernovaChainCore()
    
    # Инициализация
    await chain_core.emergency_initialize()
    
    # Получение статуса
    status = chain_core.get_status()
    print(status)

asyncio.run(main())
```

### Работа с транзакциями

```python
# Добавление транзакции
await chain_core.add_transaction(
    sender="alice",
    receiver="bob",
    amount=100.0,
    data={"memo": "payment for services"}
)

# Майнинг блока
block = await chain_core.mine_block("miner_address")

# Проверка баланса
balance = chain_core.get_balance("alice")
print(f"Alice balance: {balance}")

# История транзакций
history = chain_core.get_transaction_history("alice")
for tx in history:
    print(f"{tx.sender} -> {tx.receiver}: {tx.amount}")
```

### Смарт-контракты

```python
# Деплой контракта
contract_code = """
state['balance'] = 1000

def transfer(to_address, amount):
    if state['balance'] >= amount:
        state['balance'] -= amount
        state[f'transfer_to_{to_address}'] = amount
        return True
    return False

def get_balance():
    return state['balance']
"""

await chain_core.deploy_contract(
    contract_id="token_001",
    owner="alice",
    code=contract_code
)

# Вызов функции контракта
result = await chain_core.call_contract(
    contract_id="token_001",
    function_name="transfer",
    args={"to_address": "bob", "amount": 300},
    caller="alice"
)

if result["success"]:
    print(f"Transfer result: {result['result']}")
    print(f"Gas used: {result['gas_used']}")
```

### Consensus Management

```python
# Доступ к consensus engine
consensus = chain_core.consensus_engine

# Добавление валидатора
consensus.add_validator("validator_001", stake=1000.0)

# Выбор валидатора (для PoS)
selected = consensus.select_validator()

# Статистика
stats = consensus.get_stats()
print(f"Total validators: {stats['total_validators']}")
print(f"Total stake: {stats['total_stake']}")
```

## 🧪 Тестирование

```bash
# Запуск всех тестов
pytest tests/test_aethernova_chain.py -v

# Запуск с coverage
pytest tests/test_aethernova_chain.py --cov=src --cov-report=html

# Запуск конкретного теста
pytest tests/test_aethernova_chain.py::TestBlockchain::test_mine_pending_transactions -v
```

### Test Coverage

- **25 comprehensive tests** покрывают все критические функции
- **Block operations**: creation, hashing, mining
- **Blockchain**: transactions, mining, validation, tampering detection
- **Consensus**: PoW/PoS validation, validator management
- **Smart Contracts**: VM execution, gas limits, state management
- **Validators**: block structure, proof of work, chain integrity

## 📊 API Reference

### AethernovaChainCore

```python
class AethernovaChainCore:
    async def emergency_initialize() -> bool
    async def emergency_start() -> None
    async def emergency_stop() -> None
    
    # Transaction API
    async def add_transaction(sender, receiver, amount, data) -> bool
    async def mine_block(miner_address) -> Optional[Block]
    def get_balance(address) -> float
    def get_transaction_history(address) -> List[Transaction]
    
    # Contract API
    async def deploy_contract(contract_id, owner, code) -> bool
    async def call_contract(contract_id, function_name, args, caller) -> Dict
    
    # Status API
    def get_status() -> Dict[str, Any]
    async def emergency_health_check() -> Dict[str, Any]
```

### Blockchain

```python
class Blockchain:
    def __init__(difficulty: int = 4, mining_reward: float = 10.0)
    
    def add_transaction(transaction: Transaction) -> bool
    async def mine_pending_transactions(miner_address: str) -> Optional[Block]
    def is_chain_valid() -> bool
    def get_balance(address: str) -> float
    def get_transaction_history(address: str) -> List[Transaction]
    def get_chain_stats() -> Dict[str, Any]
    
    async def save_to_file(filename: str) -> None
    @staticmethod
    async def load_from_file(filename: str) -> Optional[Blockchain]
```

### ConsensusEngine

```python
class ConsensusEngine:
    def __init__(consensus_type: ConsensusType, min_validators: int)
    
    def add_validator(validator_id: str, stake: float) -> bool
    def remove_validator(validator_id: str) -> bool
    def select_validator() -> Optional[str]
    async def validate_block(block: Block, validator_id: str, difficulty: int) -> bool
    def get_stats() -> Dict[str, Any]
```

### ContractManager

```python
class ContractManager:
    async def deploy_contract(contract_id: str, owner: str, code: str) -> None
    async def call_contract(contract_id, function_name, args, caller) -> Dict
    def get_contract(contract_id: str) -> Optional[SmartContract]
    def get_stats() -> Dict[str, Any]
```

## 🔒 Безопасность

- **Hash-based integrity**: SHA-256 для всех блоков и транзакций
- **Chain validation**: Полная проверка цепи на целостность
- **PoW security**: Защита от модификации истории
- **Contract sandboxing**: Изолированное выполнение смарт-контрактов
- **Gas metering**: Защита от бесконечных циклов
- **Validator consensus**: Распределенное подтверждение блоков

## ⚙️ Конфигурация

```python
# config.py
class Config:
    system_name: str = "aethernova-chain-core"
    version: str = "1.0.0-emergency"
    
    # Blockchain settings
    blockchain_difficulty: int = 4  # PoW difficulty
    mining_reward: float = 10.0     # Block reward
    block_time_target: int = 10     # Target seconds per block
    
    # Consensus settings
    consensus_type: str = "proof_of_work"
    min_validators: int = 3
    
    # Contract settings
    contract_gas_limit: int = 100000
    contract_timeout: float = 5.0
    
    # Persistence
    chain_data_file: str = "data/blockchain.json"
```

## 📈 Метрики

Система отслеживает:
- `processed_blocks` - Количество обработанных блоков
- `processed_transactions` - Количество обработанных транзакций
- `uptime_seconds` - Время работы системы
- `error_count` - Количество ошибок
- `last_health_check` - Время последней проверки

## 🔄 Архитектура

```
┌─────────────────────────────────────────────┐
│       AethernovaChainCore (Main)            │
├─────────────────────────────────────────────┤
│  - Emergency initialization                 │
│  - Component orchestration                  │
│  - API endpoints                            │
└──────────────┬──────────────────────────────┘
               │
    ┌──────────┴──────────┐
    │                     │
┌───▼────────┐    ┌──────▼─────────┐
│ Blockchain │    │ ConsensusEngine│
├────────────┤    ├────────────────┤
│ - Chain    │    │ - Validators   │
│ - Pending  │    │ - Selection    │
│ - Mining   │    │ - Validation   │
└────┬───────┘    └────────────────┘
     │
┌────▼──────────┐    ┌──────────────┐
│ Block/TX      │    │ ContractMgr  │
├───────────────┤    ├──────────────┤
│ - Hashing     │    │ - Deployment │
│ - Mining      │    │ - Execution  │
│ - Validation  │    │ - State      │
└───────────────┘    └──────────────┘
```

## 🚨 Emergency Mode

Система работает в **Emergency Operational** режиме:
- ✅ Все критические компоненты инициализированы
- ✅ Blockchain валидация активна
- ✅ Consensus работает
- ✅ Smart contracts доступны
- ✅ Мониторинг активен

## 📝 Примеры использования

### Создание простого токена

```python
token_contract = """
state['total_supply'] = 1000000
state['balances'] = {}

def mint(address, amount):
    if caller == state.get('owner'):
        state['balances'][address] = state['balances'].get(address, 0) + amount
        return True
    return False

def transfer(to, amount):
    balance = state['balances'].get(caller, 0)
    if balance >= amount:
        state['balances'][caller] = balance - amount
        state['balances'][to] = state['balances'].get(to, 0) + amount
        return True
    return False

def balance_of(address):
    return state['balances'].get(address, 0)
"""

await chain_core.deploy_contract("my_token", "alice", token_contract)
```

### Mining Loop

```python
async def mining_loop(miner_address: str):
    while True:
        # Проверяем наличие pending транзакций
        if len(chain_core.blockchain.pending_transactions) > 0:
            block = await chain_core.mine_block(miner_address)
            print(f"Mined block {block.index}: {block.hash}")
        
        await asyncio.sleep(1)
```

## 🆘 Troubleshooting

### Blockchain не валидируется
```python
# Проверка целостности цепи
if not chain_core.blockchain.is_chain_valid():
    print("Chain integrity compromised!")
    # Перезагрузка из бэкапа
    chain_core.blockchain = await Blockchain.load_from_file("backup.json")
```

### Контракт превышает gas limit
```python
# Увеличение gas limit
chain_core.contract_manager.gas_limit = 200000

# Или оптимизация кода контракта
```

### Mining слишком медленный
```python
# Уменьшение сложности для development
chain_core.blockchain.difficulty = 2
```

## 📚 Dependencies

- `Python >= 3.10`
- `loguru` - Structured logging
- `pydantic` - Configuration validation
- `pytest` - Testing framework
- `pytest-asyncio` - Async test support

## 🎯 Следующие шаги

1. ✅ Blockchain core восстановлен
2. ✅ Consensus engine реализован
3. ✅ Smart contracts работают
4. ✅ Tests написаны (25 tests)
5. ⏳ Performance optimization
6. ⏳ P2P networking
7. ⏳ Advanced consensus (BFT)

## 📞 Поддержка

При проблемах проверьте:
1. Логи в `logs/aethernova-chain-core.emergency.log`
2. Health check: `await chain_core.emergency_health_check()`
3. Chain stats: `chain_core.blockchain.get_chain_stats()`
4. Component status: `chain_core.get_status()`

---

**Восстановлено**: 2025-10-10  
**Статус**: ✅ Emergency Operational  
**Coverage**: 25 tests, blockchain + consensus + smart contracts  
**Priority**: 9/10 Critical
