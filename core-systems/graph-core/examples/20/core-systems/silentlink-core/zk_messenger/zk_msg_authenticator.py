import os
import time
import hashlib
import logging
from typing import Optional

from silentlink_core.crypto.zk.snark import generate_zk_proof, verify_zk_proof
from silentlink_core.crypto.keys import generate_ephemeral_keypair, sign_blind, verify_blind_signature
from silentlink_core.security.nonce_manager import NonceManager
from silentlink_core.protocols.zk_context import ZKContext

logger = logging.getLogger("zk_messenger.zk_authenticator")
logging.basicConfig(level=logging.INFO)

class ZKMessageAuthenticator:
    def __init__(self, context: ZKContext):
        self.context = context
        self.nonce_manager = NonceManager(ttl_sec=300)

    def _hash_message(self, message: bytes) -> str:
        digest = hashlib.sha3_256(message).hexdigest()
        logger.debug(f"Hashed message: {digest}")
        return digest

    def _generate_ephemeral_proof(self, payload_hash: str) -> dict:
        zk_input = {
            "user_id": self.context.user_id,
            "payload_hash": payload_hash,
            "session_nonce": self.nonce_manager.issue(),
        }
        logger.debug("Generating zero-knowledge proof...")
        proof = generate_zk_proof(zk_input, circuit="msg_auth")
        return {
            "proof": proof,
            "public_inputs": zk_input
        }

    def sign_and_prove(self, message: bytes) -> dict:
        try:
            payload_hash = self._hash_message(message)
            ephemeral_keys = generate_ephemeral_keypair()
            blind_signature = sign_blind(message, ephemeral_keys.private_key)

            zk_bundle = self._generate_ephemeral_proof(payload_hash)
            logger.info("Message signed and ZK proof generated successfully")
            return {
                "signature": blind_signature,
                "zk_proof": zk_bundle["proof"],
                "public_inputs": zk_bundle["public_inputs"],
                "ephemeral_pubkey": ephemeral_keys.public_key,
                "timestamp": time.time(),
            }

        except Exception as e:
            logger.error(f"Authentication error: {e}")
            raise

    def verify_incoming(self, message: bytes, signature: str, public_inputs: dict, proof: str, sender_pubkey: str) -> bool:
        try:
            if not self.nonce_manager.validate(public_inputs["session_nonce"]):
                logger.warning("Rejected: reused or invalid nonce")
                return False

            if not verify_blind_signature(message, signature, sender_pubkey):
                logger.warning("Invalid blind signature")
                return False

            if not verify_zk_proof(proof, public_inputs, circuit="msg_auth"):
                logger.warning("ZK proof verification failed")
                return False

            logger.info("Message successfully authenticated via ZK + blind signature")
            return True

        except Exception as e:
            logger.error(f"Verification failed: {e}")
            return False
