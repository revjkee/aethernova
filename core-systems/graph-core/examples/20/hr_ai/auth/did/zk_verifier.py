# hr_ai/auth/did/zk_verifier.py

import logging
from typing import Dict
from dataclasses import dataclass

from eth_typing import HexStr
from eth_utils import is_hex
from web3 import Web3
from hr_ai.auth.did.did_config_loader import get_did_config

from semaphore_utils.verifier import SemaphoreVerifierContract
from semaphore_utils.proof_parser import parse_semaphore_proof
from semaphore_utils.exceptions import InvalidProofError

logger = logging.getLogger("ZKVerifier")


@dataclass
class ProofPayload:
    proof: Dict
    group_id: str
    signal: str
    external_nullifier: str


class SemaphoreVerifier:
    def __init__(self):
        self.config = get_did_config()
        self.contract_address = Web3.to_checksum_address(
            self.config["zk_proof"]["verifier_contract"]["address"]
        )
        self.rpc_url = self.config["zk_proof"]["verifier_contract"]["rpc_url"]
        self.web3 = Web3(Web3.HTTPProvider(self.rpc_url))
        self.contract = SemaphoreVerifierContract(
            web3=self.web3,
            contract_address=self.contract_address
        )

    def verify_proof(self, proof: Dict, group_id: str, signal: str, external_nullifier: str) -> bool:
        try:
            logger.debug(f"Verifying ZK proof for group {group_id}, signal {signal}")
            parsed_proof = parse_semaphore_proof(proof)

            if not self._validate_fields(parsed_proof):
                logger.warning("Proof field validation failed")
                return False

            signal_hash = self._hash_signal(signal)
            nullifier_hash = self._hash_signal(external_nullifier)

            is_valid = self.contract.verify_proof(
                merkle_root=parsed_proof["merkle_root"],
                nullifier_hash=nullifier_hash,
                signal_hash=signal_hash,
                external_nullifier=external_nullifier,
                proof=parsed_proof["proof"]
            )

            logger.info(f"ZK proof verification result: {is_valid}")
            return is_valid

        except InvalidProofError as e:
            logger.error(f"Invalid ZK proof structure: {str(e)}")
            return False

        except Exception as e:
            logger.exception(f"Error during ZK proof verification: {str(e)}")
            return False

    def _validate_fields(self, parsed_proof: Dict) -> bool:
        required_fields = ["proof", "merkle_root", "nullifier_hash"]
        for field in required_fields:
            if field not in parsed_proof:
                logger.error(f"Missing required proof field: {field}")
                return False
            if not is_hex(parsed_proof[field]):
                logger.error(f"Invalid hex in field: {field}")
                return False
        return True

    def _hash_signal(self, signal: str) -> HexStr:
        # Hash signal using keccak256 as required by Semaphore spec
        hashed = Web3.keccak(text=signal)
        return Web3.to_hex(hashed)
