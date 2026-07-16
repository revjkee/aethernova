"""
Smart Contracts - AetherNova Chain Core
Система смарт-контрактов и виртуальная машина
"""

import asyncio
import json
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime
from enum import Enum
from loguru import logger


class ContractState(str, Enum):
    """Состояния контракта"""
    DEPLOYED = "deployed"
    ACTIVE = "active"
    PAUSED = "paused"
    TERMINATED = "terminated"


class SmartContract:
    """Базовый класс смарт-контракта"""
    
    def __init__(
        self,
        contract_id: str,
        owner: str,
        code: str,
        state: Dict[str, Any] = None
    ):
        self.contract_id = contract_id
        self.owner = owner
        self.code = code
        self.state = state or {}
        self.status = ContractState.DEPLOYED
        self.created_at = datetime.now().timestamp()
        self.last_executed = None
        self.execution_count = 0
        self.balance = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Преобразует контракт в словарь"""
        return {
            "contract_id": self.contract_id,
            "owner": self.owner,
            "code": self.code,
            "state": self.state,
            "status": self.status.value,
            "created_at": self.created_at,
            "last_executed": self.last_executed,
            "execution_count": self.execution_count,
            "balance": self.balance
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SmartContract':
        """Создаёт контракт из словаря"""
        contract = cls(
            contract_id=data['contract_id'],
            owner=data['owner'],
            code=data['code'],
            state=data.get('state', {})
        )
        contract.status = ContractState(data.get('status', 'deployed'))
        contract.created_at = data.get('created_at', datetime.now().timestamp())
        contract.last_executed = data.get('last_executed')
        contract.execution_count = data.get('execution_count', 0)
        contract.balance = data.get('balance', 0.0)
        return contract


class ContractVM:
    """Виртуальная машина для выполнения смарт-контрактов"""
    
    def __init__(self, gas_limit: int = 1000000):
        self.gas_limit = gas_limit
        self.gas_price = 0.00001  # Цена за единицу газа
        self.builtin_functions = {
            "transfer": self._builtin_transfer,
            "balance_of": self._builtin_balance_of,
            "emit_event": self._builtin_emit_event,
            "timestamp": self._builtin_timestamp,
        }
        self.events: List[Dict[str, Any]] = []
        
        logger.info("🖥️ Contract VM инициализирована")
    
    async def execute(
        self,
        contract: SmartContract,
        function_name: str,
        args: Dict[str, Any],
        caller: str,
        value: float = 0.0
    ) -> Dict[str, Any]:
        """
        Выполняет функцию контракта
        
        Args:
            contract: Контракт для выполнения
            function_name: Имя функции
            args: Аргументы функции
            caller: Адрес вызывающего
            value: Количество отправляемых токенов
            
        Returns:
            Результат выполнения
        """
        if contract.status != ContractState.ACTIVE:
            return {
                "success": False,
                "error": f"Contract is not active: {contract.status}"
            }
        
        gas_used = 0
        
        try:
            logger.debug(f"🔄 Выполнение контракта {contract.contract_id}.{function_name}()")
            
            # Создаём контекст выполнения
            context = {
                "contract": contract,
                "caller": caller,
                "value": value,
                "gas_used": gas_used,
                "gas_limit": self.gas_limit,
                "timestamp": datetime.now().timestamp(),
                "builtins": self.builtin_functions
            }
            
            # Парсим и выполняем код (упрощенная версия)
            result = await self._execute_function(
                contract,
                function_name,
                args,
                context
            )
            
            # Обновляем состояние контракта
            contract.last_executed = datetime.now().timestamp()
            contract.execution_count += 1
            contract.balance += value
            
            gas_used = result.get("gas_used", 21000)
            gas_cost = gas_used * self.gas_price
            
            logger.info(f"✅ Контракт выполнен. Gas: {gas_used}, Cost: {gas_cost}")
            
            return {
                "success": True,
                "result": result.get("return_value"),
                "gas_used": gas_used,
                "gas_cost": gas_cost,
                "events": self.events.copy()
            }
            
        except Exception as e:
            logger.error(f"❌ Ошибка выполнения контракта: {e}")
            return {
                "success": False,
                "error": str(e),
                "gas_used": gas_used,
                "gas_cost": gas_used * self.gas_price
            }
        finally:
            self.events.clear()
    
    async def _execute_function(
        self,
        contract: SmartContract,
        function_name: str,
        args: Dict[str, Any],
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Выполняет функцию контракта"""
        gas_used = 21000  # Базовая стоимость
        
        # Проверка встроенных функций
        if function_name in self.builtin_functions:
            result = await self.builtin_functions[function_name](
                contract,
                args,
                context
            )
            return {
                "return_value": result,
                "gas_used": gas_used + 5000
            }
        
        # Парсинг кода контракта (упрощенный)
        try:
            code_obj = json.loads(contract.code)
        except:
            # Если код не JSON, выполняем как Python (опасно в production!)
            code_obj = {"type": "python", "source": contract.code}
        
        if code_obj.get("type") == "simple":
            # Простой контракт с предопределенными функциями
            functions = code_obj.get("functions", {})
            
            if function_name not in functions:
                raise ValueError(f"Function {function_name} not found")
            
            func_code = functions[function_name]
            result = await self._execute_simple_function(
                func_code,
                args,
                contract,
                context
            )
            
            return {
                "return_value": result,
                "gas_used": gas_used + len(str(func_code)) * 10
            }
        
        # Для других типов контрактов
        raise NotImplementedError(f"Contract type {code_obj.get('type')} not supported")
    
    async def _execute_simple_function(
        self,
        func_code: Dict[str, Any],
        args: Dict[str, Any],
        contract: SmartContract,
        context: Dict[str, Any]
    ) -> Any:
        """Выполняет простую функцию контракта"""
        operations = func_code.get("operations", [])
        result = None
        
        for op in operations:
            op_type = op.get("type")
            
            if op_type == "set_state":
                key = op["key"]
                value = op.get("value")
                # Подстановка аргументов
                if isinstance(value, str) and value.startswith("$"):
                    value = args.get(value[1:])
                contract.state[key] = value
            
            elif op_type == "get_state":
                key = op["key"]
                result = contract.state.get(key)
            
            elif op_type == "transfer":
                to_address = op["to"]
                amount = op["amount"]
                if isinstance(amount, str) and amount.startswith("$"):
                    amount = args.get(amount[1:])
                
                if contract.balance >= amount:
                    contract.balance -= amount
                    # В реальной системе здесь была бы транзакция
                    result = True
                else:
                    raise ValueError("Insufficient contract balance")
            
            elif op_type == "return":
                value = op.get("value")
                if isinstance(value, str) and value.startswith("$"):
                    value = args.get(value[1:])
                result = value
        
        return result
    
    async def _builtin_transfer(
        self,
        contract: SmartContract,
        args: Dict[str, Any],
        context: Dict[str, Any]
    ) -> bool:
        """Встроенная функция перевода"""
        to_address = args.get("to")
        amount = args.get("amount", 0)
        
        if contract.balance >= amount:
            contract.balance -= amount
            logger.debug(f"💸 Transfer: {amount} to {to_address}")
            return True
        
        return False
    
    async def _builtin_balance_of(
        self,
        contract: SmartContract,
        args: Dict[str, Any],
        context: Dict[str, Any]
    ) -> float:
        """Встроенная функция получения баланса"""
        address = args.get("address")
        if address == contract.contract_id:
            return contract.balance
        return 0.0
    
    async def _builtin_emit_event(
        self,
        contract: SmartContract,
        args: Dict[str, Any],
        context: Dict[str, Any]
    ) -> bool:
        """Встроенная функция генерации события"""
        event = {
            "contract_id": contract.contract_id,
            "event_name": args.get("name"),
            "data": args.get("data", {}),
            "timestamp": datetime.now().timestamp()
        }
        self.events.append(event)
        logger.debug(f"📢 Event: {event['event_name']}")
        return True
    
    async def _builtin_timestamp(
        self,
        contract: SmartContract,
        args: Dict[str, Any],
        context: Dict[str, Any]
    ) -> float:
        """Встроенная функция получения времени"""
        return context["timestamp"]


class ContractManager:
    """Менеджер смарт-контрактов"""
    
    def __init__(self):
        self.contracts: Dict[str, SmartContract] = {}
        self.vm = ContractVM()
        
        logger.info("📋 Contract Manager инициализирован")
    
    async def deploy_contract(
        self,
        contract_id: str,
        owner: str,
        code: str,
        initial_state: Dict[str, Any] = None
    ) -> SmartContract:
        """Деплоит контракт"""
        if contract_id in self.contracts:
            raise ValueError(f"Contract {contract_id} already exists")
        
        contract = SmartContract(
            contract_id=contract_id,
            owner=owner,
            code=code,
            state=initial_state or {}
        )
        
        contract.status = ContractState.ACTIVE
        self.contracts[contract_id] = contract
        
        logger.info(f"✅ Контракт деплоен: {contract_id}")
        return contract
    
    async def call_contract(
        self,
        contract_id: str,
        function_name: str,
        args: Dict[str, Any],
        caller: str,
        value: float = 0.0
    ) -> Dict[str, Any]:
        """Вызывает функцию контракта"""
        if contract_id not in self.contracts:
            return {
                "success": False,
                "error": f"Contract {contract_id} not found"
            }
        
        contract = self.contracts[contract_id]
        return await self.vm.execute(contract, function_name, args, caller, value)
    
    def get_contract(self, contract_id: str) -> Optional[SmartContract]:
        """Получает контракт по ID"""
        return self.contracts.get(contract_id)
    
    def pause_contract(self, contract_id: str, owner: str) -> bool:
        """Приостанавливает контракт"""
        contract = self.contracts.get(contract_id)
        if not contract:
            return False
        
        if contract.owner != owner:
            logger.warning(f"⚠️ Только владелец может приостановить контракт")
            return False
        
        contract.status = ContractState.PAUSED
        logger.info(f"⏸️ Контракт приостановлен: {contract_id}")
        return True
    
    def resume_contract(self, contract_id: str, owner: str) -> bool:
        """Возобновляет контракт"""
        contract = self.contracts.get(contract_id)
        if not contract:
            return False
        
        if contract.owner != owner:
            logger.warning(f"⚠️ Только владелец может возобновить контракт")
            return False
        
        contract.status = ContractState.ACTIVE
        logger.info(f"▶️ Контракт возобновлён: {contract_id}")
        return True
    
    def get_stats(self) -> Dict[str, Any]:
        """Возвращает статистику контрактов"""
        return {
            "total_contracts": len(self.contracts),
            "active_contracts": sum(
                1 for c in self.contracts.values()
                if c.status == ContractState.ACTIVE
            ),
            "paused_contracts": sum(
                1 for c in self.contracts.values()
                if c.status == ContractState.PAUSED
            ),
            "total_executions": sum(
                c.execution_count for c in self.contracts.values()
            )
        }
