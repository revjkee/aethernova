# utils/abi_loader.py

import json
import os
from pathlib import Path
from functools import lru_cache
from utils.logger import logger

ABI_BASE_PATH = Path("onchain") / "abi"

class AbiLoaderError(Exception):
    """Custom error for ABI loading issues."""
    pass

@lru_cache(maxsize=64)
def load_contract_abi(contract_name: str) -> list:
    """
    Loads the ABI JSON for a given contract name from onchain/abi/.

    Args:
        contract_name (str): Contract identifier, e.g., 'ERC20', 'DAO'

    Returns:
        list: Parsed ABI list

    Raises:
        AbiLoaderError: if file missing or malformed
    """
    filename = ABI_BASE_PATH / f"{contract_name}.json"
    if not filename.exists():
        msg = f"ABI file not found: {filename}"
        logger.error(f"[ABI Loader] {msg}")
        raise AbiLoaderError(msg)

    try:
        with open(filename, "r", encoding="utf-8") as f:
            abi = json.load(f)

        if not isinstance(abi, list):
            raise ValueError("ABI must be a list of JSON objects")

        logger.debug(f"[ABI Loader] Loaded ABI for {contract_name} ({len(abi)} entries)")
        return abi

    except (json.JSONDecodeError, ValueError) as e:
        msg = f"Malformed ABI file for {contract_name}: {e}"
        logger.error(f"[ABI Loader] {msg}")
        raise AbiLoaderError(msg)
