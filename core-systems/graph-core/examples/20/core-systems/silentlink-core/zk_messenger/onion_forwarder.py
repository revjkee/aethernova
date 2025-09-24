import os
import time
import json
import random
import logging
from typing import List, Dict, Optional
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from silentlink_core.zk_messenger.relay_graph import resolve_next_hop
from silentlink_core.crypto.zk.zk_envelope import wrap_with_zk_layer, unwrap_zk_layer
from silentlink_core.security.delay_buffer import inject_timedelay
from silentlink_core.obfuscation.garlic_bundler import bundle_payload

logger = logging.getLogger("zk_messenger.onion_forwarder")
logging.basicConfig(level=logging.INFO)

class OnionForwarder:
    def __init__(self, node_id: str, private_key: X25519PrivateKey, relay_topology: Dict[str, str]):
        self.node_id = node_id
        self.private_key = private_key
        self.public_key = private_key.public_key()
        self.relay_topology = relay_topology

    def _decrypt_layer(self, envelope: dict) -> dict:
        try:
            shared_key = self.private_key.exchange(
                X25519PublicKey.from_public_bytes(bytes.fromhex(envelope['ephemeral_pub']))
            )
            nonce = bytes.fromhex(envelope['nonce'])
            ciphertext = bytes.fromhex(envelope['ciphertext'])

            key = HKDF(algorithm=None, length=32, salt=None, info=b"onion-route").derive(shared_key)
            cipher = ChaCha20Poly1305(key)
            plaintext = cipher.decrypt(nonce, ciphertext, associated_data=None)
            return json.loads(plaintext.decode('utf-8'))
        except Exception as e:
            logger.error(f"Failed to decrypt onion layer: {e}")
            raise

    def _encrypt_layer(self, payload: dict, recipient_pubkey: bytes) -> dict:
        try:
            ephemeral_key = X25519PrivateKey.generate()
            shared_key = ephemeral_key.exchange(X25519PublicKey.from_public_bytes(recipient_pubkey))
            nonce = os.urandom(12)
            key = HKDF(algorithm=None, length=32, salt=None, info=b"onion-route").derive(shared_key)
            cipher = ChaCha20Poly1305(key)
            ciphertext = cipher.encrypt(nonce, json.dumps(payload).encode('utf-8'), associated_data=None)

            return {
                'ephemeral_pub': ephemeral_key.public_key().public_bytes_raw().hex(),
                'nonce': nonce.hex(),
                'ciphertext': ciphertext.hex()
            }
        except Exception as e:
            logger.error(f"Failed to encrypt onion layer: {e}")
            raise

    def route_message(self, payload: dict, destination_chain: List[str]) -> dict:
        try:
            # Garlic: добавление примеси
            mixed_payload = bundle_payload(payload, noise_count=3)
            wrapped = mixed_payload
            for node in reversed(destination_chain):
                next_pubkey = bytes.fromhex(self.relay_topology[node])
                wrapped = self._encrypt_layer({
                    'next_node': node,
                    'payload': wrapped
                }, next_pubkey)

            # ZK Layer: zk-обертка маршрута
            final_message = wrap_with_zk_layer(wrapped, self.node_id)
            return final_message
        except Exception as e:
            logger.error(f"Route assembly failed: {e}")
            raise

    def receive_message(self, zk_envelope: dict) -> Optional[dict]:
        try:
            # Проверка zk-подписи маршрута
            payload = unwrap_zk_layer(zk_envelope)
            decrypted = self._decrypt_layer(payload)

            # Анти-трассировка: пауза с джиттером
            inject_timedelay(jitter=0.2)

            if decrypted.get("next_node") == self.node_id:
                logger.info("Final recipient reached.")
                return decrypted["payload"]
            else:
                next_hop = decrypted["next_node"]
                forward_payload = decrypted["payload"]
                logger.info(f"Forwarding to next node: {next_hop}")
                return self.route_message(forward_payload, resolve_next_hop(self.relay_topology, next_hop))

        except Exception as e:
            logger.error(f"Failed to handle incoming message: {e}")
            return None
