# autopwn-framework/core/executor.py

import importlib
import traceback
import logging
import asyncio
import time
from types import ModuleType
from typing import Any, Dict, Optional

from autopwn_framework.core.models import ModuleResult, ExecutionContext
from autopwn_framework.core.sandbox import execute_in_sandbox
from autopwn_framework.core.logger import get_module_logger

class ModuleExecutor:
    def __init__(self, context: ExecutionContext):
        self.context = context
        self.logger = get_module_logger(context.module_name)
        self.result: Optional[ModuleResult] = None
        self.module: Optional[ModuleType] = None
        self.start_time: float = 0
        self.end_time: float = 0

    def load_module(self) -> None:
        try:
            self.logger.debug(f"Loading module: {self.context.module_name}")
            self.module = importlib.import_module(f"autopwn_framework.modules.{self.context.module_name}")
            assert hasattr(self.module, "run"), "Module must define a `run(context)` coroutine"
        except Exception as e:
            self.logger.error(f"Failed to load module: {e}")
            raise

    async def run(self) -> ModuleResult:
        self.start_time = time.time()

        try:
            self.load_module()

            if getattr(self.module, "REQUIRES_SANDBOX", False):
                self.logger.info("Running module in sandboxed environment")
                output = await execute_in_sandbox(self.module, self.context)
            else:
                self.logger.info("Executing module directly")
                output = await self.module.run(self.context)

            self.end_time = time.time()

            self.result = ModuleResult(
                module_name=self.context.module_name,
                status="success",
                output=output,
                start_time=self.start_time,
                end_time=self.end_time,
                duration=self.end_time - self.start_time
            )

        except Exception as e:
            self.end_time = time.time()
            self.logger.error(f"Execution failed: {e}")
            self.logger.debug(traceback.format_exc())

            self.result = ModuleResult(
                module_name=self.context.module_name,
                status="failed",
                output=str(e),
                start_time=self.start_time,
                end_time=self.end_time,
                duration=self.end_time - self.start_time
            )

        return self.result

    def summary(self) -> Dict[str, Any]:
        if not self.result:
            return {"error": "Module has not been executed yet"}
        return {
            "module": self.result.module_name,
            "status": self.result.status,
            "duration": round(self.result.duration, 3),
            "output": self.result.output
        }
