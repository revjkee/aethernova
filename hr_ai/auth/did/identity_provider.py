# hr_ai/auth/did/identity_provider.py

from abc import ABC, abstractmethod
from typing import Optional, Dict, Union
import logging

from eth_account import Account
from web3 import Web3
from hr_ai.auth.did.did_config_loader import get_did_config

logger = logging.getLogger("DIDProvider")


class AbstractDIDProvider(ABC):
    @abstractmethod
    def create_identity(self, metadata: Optional[Dict] = None) -> Dict:
        pass

    @abstractmethod
    def resolve(self, did: str) -> Optional[Dict]:
        pass

    @abstractmethod
    def validate_claim(self, did: str, claim: Dict) -> bool:
        pass


class EthrDIDProvider(AbstractDIDProvider):
    def __init__(self, registry_contract: str, rpc_url: str):
        self.web3 = Web3(Web3.HTTPProvider(rpc_url))
        self.registry_address = Web3.to_checksum_address(registry_contract)
        self.config = get_did_config()
        self.account = Account.create()

    def create_identity(self, metadata: Optional[Dict] = None) -> Dict:
        did = f"did:ethr:{self.account.address}"
        logger.info(f"Created new Ethr DID: {did}")
        return {
            "did": did,
            "publicKey": self.account._key_obj.public_key.to_hex(),
            "metadata": metadata or {}
        }

    def resolve(self, did: str) -> Optional[Dict]:
        if not did.startswith("did:ethr:"):
            return None
        # Псевдо-резолвинг, реальную реализацию можно подключить через ethr-did-resolver
        address = did.split(":")[-1]
        logger.debug(f"Resolved DID to address: {address}")
        return {
            "did": did,
            "address": address
        }

    def validate_claim(self, did: str, claim: Dict) -> bool:
        expected = claim.get("recipient") == did
        if not expected:
            logger.warning(f"Claim recipient mismatch for DID {did}")
        return expected


class KeyDIDProvider(AbstractDIDProvider):
    def __init__(self):
        self.account = Account.create()

    def create_identity(self, metadata: Optional[Dict] = None) -> Dict:
        did = f"did:key:{self.account.address}"
        return {
            "did": did,
            "publicKey": self.account._key_obj.public_key.to_hex(),
            "metadata": metadata or {}
        }

    def resolve(self, did: str) -> Optional[Dict]:
        if did.startswith("did:key:"):
            return {"did": did}
        return None

    def validate_claim(self, did: str, claim: Dict) -> bool:
        return claim.get("recipient") == did


def get_provider(method: str) -> AbstractDIDProvider:
    config = get_did_config()
    if method == "ethr":
        net = config["resolver"]["networks"][0]
        return EthrDIDProvider(
            registry_contract=config["resolver"]["registry_contract"],
            rpc_url=net["rpc_url"]
        )
    elif method == "key":
        return KeyDIDProvider()
    else:
        raise ValueError(f"Unsupported DID method: {method}")
