# genius_core/mutation/api_contract_checker.py

import json
import logging
import inspect
import hashlib
from typing import Dict, List, Optional, Any

from genius_core.mutation.lineage_tracker import LineageTracker
from genius_core.mutation.memory_archive import SemanticMemory

logger = logging.getLogger("APIContractChecker")


class APIContractChecker:
    def __init__(
        self,
        contract_path: str = "genius_core/mutation/contracts/api_contracts.json",
        strict: bool = True
    ):
        self.contract_path = contract_path
        self.strict = strict
        self.contracts = self._load_contracts()
        self.lineage = LineageTracker()
        self.semantic_memory = SemanticMemory()

    def _load_contracts(self) -> Dict[str, Dict[str, Any]]:
        try:
            with open(self.contract_path, "r") as f:
                contracts = json.load(f)
                logger.info(f"Loaded {len(contracts)} API contracts.")
                return contracts
        except FileNotFoundError:
            logger.warning(f"API contract file not found: {self.contract_path}")
            return {}
        except Exception as e:
            logger.error(f"Failed to load contracts: {str(e)}")
            return {}

    def validate_contract(self, module_path: str, api_name: str) -> Dict[str, Any]:
        try:
            module = self._import_module(module_path)
            function = getattr(module, api_name)
            signature = inspect.signature(function)
            docstring = inspect.getdoc(function) or ""
        except Exception as e:
            return self._fail(api_name, f"Failed to resolve: {str(e)}")

        current_contract = {
            "signature": str(signature),
            "doc_hash": self._hash(docstring),
            "args": list(signature.parameters.keys())
        }

        expected_contract = self.contracts.get(api_name)
        if not expected_contract:
            return self._warn(api_name, "No baseline contract found.")

        issues = []
        if expected_contract["signature"] != current_contract["signature"]:
            issues.append("Signature mismatch")

        if expected_contract["doc_hash"] != current_contract["doc_hash"]:
            issues.append("Docstring hash mismatch")

        if set(expected_contract["args"]) != set(current_contract["args"]):
            issues.append("Arguments mismatch")

        if issues:
            self.lineage.mark_incompatible(api_name, issues)
            return self._fail(api_name, "Contract violation", extra={"issues": issues})

        return self._pass(api_name)

    def export_contract(self, module_path: str, api_name: str) -> bool:
        try:
            module = self._import_module(module_path)
            func = getattr(module, api_name)
            signature = str(inspect.signature(func))
            docstring = inspect.getdoc(func) or ""
            self.contracts[api_name] = {
                "signature": signature,
                "doc_hash": self._hash(docstring),
                "args": list(inspect.signature(func).parameters.keys())
            }
            with open(self.contract_path, "w") as f:
                json.dump(self.contracts, f, indent=2)
            logger.info(f"Exported contract for {api_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to export contract for {api_name}: {str(e)}")
            return False

    def _import_module(self, module_path: str):
        components = module_path.split(".")
        module = __import__(components[0])
        for comp in components[1:]:
            module = getattr(module, comp)
        return module

    def _hash(self, text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def _pass(self, api_name: str) -> Dict[str, Any]:
        logger.info(f"[{api_name}] API contract OK")
        return {
            "api": api_name,
            "status": "passed",
            "strict": self.strict
        }

    def _fail(self, api_name: str, reason: str, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        logger.error(f"[{api_name}] Contract failed: {reason}")
        result = {
            "api": api_name,
            "status": "failed",
            "reason": reason,
            "strict": self.strict
        }
        if extra:
            result.update(extra)
        return result

    def _warn(self, api_name: str, message: str) -> Dict[str, Any]:
        logger.warning(f"[{api_name}] Contract warning: {message}")
        return {
            "api": api_name,
            "status": "warning",
            "message": message,
            "strict": self.strict
        }
