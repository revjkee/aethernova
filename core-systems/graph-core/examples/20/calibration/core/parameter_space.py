from typing import Any, Dict, List, Union, Optional, Callable
import random
import math
import logging

logger = logging.getLogger("parameter_space")

class ParameterValidationError(Exception):
    pass

class ParameterSpace:
    def __init__(self):
        self.space: Dict[str, Dict[str, Any]] = {}
        self.constraints: List[Callable[[Dict[str, Any]], bool]] = []

    def define_param(self, name: str, param_type: str,
                     min_val: Optional[float] = None,
                     max_val: Optional[float] = None,
                     choices: Optional[List[Any]] = None,
                     default: Optional[Any] = None):
        if param_type not in ["int", "float", "categorical", "bool"]:
            raise ParameterValidationError(f"Unsupported parameter type: {param_type}")
        
        self.space[name] = {
            "type": param_type,
            "min": min_val,
            "max": max_val,
            "choices": choices,
            "default": default
        }
        logger.debug(f"Defined parameter '{name}' with config: {self.space[name]}")

    def set_constraints(self, constraint_fn: Callable[[Dict[str, Any]], bool]):
        self.constraints.append(constraint_fn)

    def validate(self, params: Dict[str, Any]) -> bool:
        for name, config in self.space.items():
            value = params.get(name)
            if value is None:
                raise ParameterValidationError(f"Missing parameter: {name}")
            if config["type"] in ["int", "float"]:
                if not (config["min"] <= value <= config["max"]):
                    raise ParameterValidationError(f"Value {value} for '{name}' out of bounds.")
            elif config["type"] == "categorical":
                if value not in config["choices"]:
                    raise ParameterValidationError(f"Invalid choice '{value}' for '{name}'")
            elif config["type"] == "bool":
                if not isinstance(value, bool):
                    raise ParameterValidationError(f"Expected boolean for '{name}'")
        for constraint in self.constraints:
            if not constraint(params):
                raise ParameterValidationError("Custom constraint validation failed")
        return True

    def get_default_config(self) -> Dict[str, Any]:
        return {
            name: cfg["default"]
            for name, cfg in self.space.items()
            if cfg["default"] is not None
        }

    def sample(self, strategy: str = "random") -> Dict[str, Any]:
        sample = {}
        for name, cfg in self.space.items():
            if cfg["type"] == "int":
                sample[name] = random.randint(cfg["min"], cfg["max"])
            elif cfg["type"] == "float":
                sample[name] = round(random.uniform(cfg["min"], cfg["max"]), 5)
            elif cfg["type"] == "categorical":
                sample[name] = random.choice(cfg["choices"])
            elif cfg["type"] == "bool":
                sample[name] = random.choice([True, False])
        for constraint in self.constraints:
            if not constraint(sample):
                return self.sample(strategy)
        logger.debug(f"Sampled config: {sample}")
        return sample

    def grid(self, resolution: int = 5) -> List[Dict[str, Any]]:
        grid_points = []
        def expand(current, keys):
            if not keys:
                grid_points.append(current.copy())
                return
            key = keys[0]
            cfg = self.space[key]
            values = []
            if cfg["type"] == "int":
                values = list(range(cfg["min"], cfg["max"] + 1))
            elif cfg["type"] == "float":
                step = (cfg["max"] - cfg["min"]) / max(1, resolution - 1)
                values = [round(cfg["min"] + i * step, 5) for i in range(resolution)]
            elif cfg["type"] == "categorical":
                values = cfg["choices"]
            elif cfg["type"] == "bool":
                values = [True, False]
            for val in values:
                current[key] = val
                expand(current, keys[1:])

        expand({}, list(self.space.keys()))
        filtered = [p for p in grid_points if all(c(p) for c in self.constraints)]
        logger.info(f"Generated {len(filtered)} grid configs")
        return filtered
