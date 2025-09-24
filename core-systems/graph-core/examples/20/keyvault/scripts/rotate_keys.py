#!/usr/bin/env python3

import sys
import asyncio
import logging
from datetime import datetime, timedelta
from keyvault.core.key_lifecycle import rotate_key, get_expiring_keys
from keyvault.core.audit_logger import log_event
from keyvault.config.vault_config import ROTATION_POLICY
from keyvault.core.secret_manager import get_secret_metadata
from keyvault.core.signing_engine import sign_payload
from keyvault.security.session_manager import system_identity

logger = logging.getLogger("rotate_keys")
logging.basicConfig(level=logging.INFO)

async def rotate_all_due_keys():
    logger.info("[Rotation] Starting key rotation process...")

    try:
        expiring_keys = await get_expiring_keys(threshold_days=ROTATION_POLICY["threshold_days"])
        if not expiring_keys:
            logger.info("[Rotation] No keys due for rotation.")
            return

        for key_id in expiring_keys:
            meta = await get_secret_metadata(key_id)
            logger.info(f"[Rotation] Rotating key: {key_id} (expires: {meta['expires_at']})")

            try:
                new_key = await rotate_key(key_id)
                signed_log = sign_payload({
                    "event": "key_rotated",
                    "key_id": key_id,
                    "new_key_id": new_key["id"],
                    "timestamp": datetime.utcnow().isoformat()
                }, identity=system_identity())

                await log_event(
                    actor="system:rotator",
                    action="rotate_key",
                    target=key_id,
                    result="success",
                    signature=signed_log
                )

                logger.info(f"[Rotation] Success: {key_id} → {new_key['id']}")

            except Exception as ex:
                logger.error(f"[Rotation] Failed to rotate {key_id}: {str(ex)}")
                await log_event(
                    actor="system:rotator",
                    action="rotate_key",
                    target=key_id,
                    result="failure",
                    details=str(ex)
                )

    except Exception as outer_ex:
        logger.critical(f"[Rotation] Fatal error: {outer_ex}")
        sys.exit(1)


def entrypoint():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(rotate_all_due_keys())
    loop.close()


if __name__ == "__main__":
    entrypoint()
