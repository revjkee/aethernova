# backend/ci/chaos-testing/registry/chaos_registry.py

import importlib
import inspect
import os
from typing import Dict, Any, Type, Optional
from pydantic import BaseModel, ValidationError

# Абстрактный интерфейс для сценариев
class ChaosScenario(BaseModel):
    name: str
    description: str
    parameters: Dict[str, Any]

    def run(self, **kwargs):
        raise NotImplementedError("Each chaos scenario must implement the 'run' method.")

# Внутренний реестр сценариев
class ChaosRegistry:
    def __init__(self):
        self._registry: Dict[str, Dict[str, Any]] = {}

    def register(self, scenario_cls: Type[ChaosScenario]):
        if not issubclass(scenario_cls, ChaosScenario):
            raise TypeError("Scenario must inherit from ChaosScenario")

        name = scenario_cls.__name__
        description = scenario_cls.__doc__ or "No description provided"
        parameters = scenario_cls.__fields__

        self._registry[name] = {
            "class": scenario_cls,
            "description": description.strip(),
            "parameters": list(parameters.keys())
        }

    def get(self, name: str) -> Optional[Type[ChaosScenario]]:
        entry = self._registry.get(name)
        return entry["class"] if entry else None

    def list(self) -> Dict[str, Dict[str, Any]]:
        return self._registry

    def validate_parameters(self, name: str, params: Dict[str, Any]) -> bool:
        scenario_cls = self.get(name)
        if not scenario_cls:
            raise ValueError(f"Scenario '{name}' not found in registry")

        try:
            scenario_cls(**params)
            return True
        except ValidationError as e:
            raise ValueError(f"Parameter validation failed: {str(e)}")

# Глобальный реестр
chaos_registry = ChaosRegistry()

# Автоматическая регистрация сценариев из директории scenarios
def auto_register_scenarios(scenarios_path: str):
    for file in os.listdir(scenarios_path):
        if file.endswith(".py") and not file.startswith("__"):
            module_name = f"backend.ci.chaos_testing.scenarios.{file[:-3]}"
            try:
                module = importlib.import_module(module_name)
                for _, obj in inspect.getmembers(module):
                    if inspect.isclass(obj) and issubclass(obj, ChaosScenario) and obj is not ChaosScenario:
                        chaos_registry.register(obj)
            except Exception as e:
                print(f"Failed to load {module_name}: {e}")

# Инициализация при импорте
current_dir = os.path.dirname(__file__)
scenarios_dir = os.path.abspath(os.path.join(current_dir, "..", "scenarios"))
auto_register_scenarios(scenarios_dir)
