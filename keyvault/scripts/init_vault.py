#!/usr/bin/env python3

import os
import sys
import asyncio
import logging
from getpass import getpass
from pathlib import Path
from keyvault.core.vault_seal import generate_master_key, seal_vault, vault_is_initialized
from keyvault.core.secret_manager import init_vault_db
from keyvault.core.audit_logger import log_event
from keyvault.core.signing_engine import sign_payload
from keyvault.security.session_manager import system_identity
from keyvault.config.vault_config import VAULT_STORAGE_PATH

logger = logging.getLogger("init_vault")
logging.basicConfig(level=logging.INFO)


async def initialize_vault():
    logger.info("[Init] Starting vault initialization...")

    if await vault_is_initialized():
        logger.warning("[Init] Vault already initialized. Aborting.")
        sys.exit(1)

    try:
        # Secure input of passphrase
        passphrase = getpass("Enter vault initialization passphrase: ").strip()
        if not passphrase or len(passphrase) < 12:
            raise ValueError("Passphrase too short")

        # Generate master key
        logger.info("[Init] Generating master key...")
        master_key = generate_master_key(passphrase)

        # Initialize encrypted database
        logger.info("[Init] Initializing vault DB...")
        await init_vault_db(master_key)

        # Seal vault with master key
        logger.info("[Init] Sealing vault...")
        await seal_vault(master_key)

        # Generate and sign initialization event
        payload = {
            "event": "vault_initialized",
            "storage_path": str(VAULT_STORAGE_PATH),
            "timestamp": asyncio.get_event_loop().time()
        }
        signed_audit = sign_payload(payload, identity=system_identity())

        # Audit log
        await log_event(
            actor="system:init",
            action="initialize_vault",
            target="vault-core",
            result="success",
            signature=signed_audit
        )

        logger.info("[Init] Vault initialized successfully.")

    except Exception as ex:
        logger.critical(f"[Init] Initialization failed: {ex}")
        await log_event(
            actor="system:init",
            action="initialize_vault",
            target="vault-core",
            result="failure",
            details=str(ex)
        )
        sys.exit(1)


def entrypoint():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(initialize_vault())
    loop.close()


if __name__ == "__main__":
    entrypoint()
