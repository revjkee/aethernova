# hr_ai/auth/did/resolver_adapter.py

import logging
from typing import Optional, Dict
from functools import lru_cache
from hr_ai.auth.did.did_config_loader import get_did_config

import requests
from web3 import Web3

logger = logging.getLogger("DIDResolver")

class DIDResolver:
    def __init__(self):
        self.config = get_did_config()
        self.web3_mainnet = None
        self.ethr_registry = self.config["resolver"]["registry_contract"]
        self.did_method = self.config["resolver"]["method"]

        for net in self.config["resolver"]["networks"]:
            if net["id"] == "1":
                self.web3_mainnet = Web3(Web3.HTTPProvider(net["rpc_url"]))

    @lru_cache(maxsize=256)
    def resolve(self, did: str) -> Optional[Dict]:
        if did.startswith("did:ethr:"):
            return self._resolve_ethr(did)
        elif did.startswith("did:key:"):
            return self._resolve_key(did)
        elif did.startswith("did:web:"):
            return self._resolve_web(did)
        else:
            logger.warning(f"Unsupported DID method: {did}")
            return None

    def resolve_by_commitment(self, identity_commitment: str) -> Optional[str]:
        # Псевдо-привязка, должна быть заменена на Merkle map / offchain-реестр
        logger.debug(f"Attempted resolution for commitment: {identity_commitment}")
        return f"did:anon:{identity_commitment[:16]}"

    def _resolve_ethr(self, did: str) -> Optional[Dict]:
        if not self.web3_mainnet:
            logger.error("Web3 provider not initialized for mainnet")
            return None
        address = did.split(":")[-1]
        logger.debug(f"Resolving Ethr DID for address: {address}")
        return {
            "did": did,
            "controller": address,
            "registry": self.ethr_registry,
            "network": "mainnet"
        }

    def _resolve_key(self, did: str) -> Dict:
        key_part = did.split(":")[-1]
        logger.debug(f"Resolving Key DID: {key_part}")
        return {
            "did": did,
            "publicKey": key_part
        }

    def _resolve_web(self, did: str) -> Optional[Dict]:
        try:
            domain = did.split(":")[2]
            url = f"https://{domain}/.well-known/did.json"
            logger.debug(f"Fetching web DID document from {url}")
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                return response.json()
            logger.warning(f"Web DID not found at {url}")
        except Exception as e:
            logger.error(f"Error resolving Web DID: {str(e)}")
        return None
