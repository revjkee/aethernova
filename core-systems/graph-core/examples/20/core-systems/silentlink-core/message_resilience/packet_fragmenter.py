import os
import uuid
import random
import logging
from typing import List, Dict, Optional, Tuple
from hashlib import sha256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from silentlink_core.security.redundancy import erasure_encode, erasure_decode
from silentlink_core.obfuscation.noise_injector import inject_dummy_packets
from silentlink_core.crypto.entropy_pad import xor_with_entropy_pad

logger = logging.getLogger("message_resilience.packet_fragmenter")
logging.basicConfig(level=logging.INFO)

MAX_FRAGMENT_SIZE = 512  # Bytes per fragment before overhead

class FragmentationError(Exception):
    pass

class PacketFragmenter:
    def __init__(self, entropy_key: bytes):
        self.entropy_key = entropy_key

    def _encrypt_fragment(self, fragment: bytes, nonce: bytes) -> bytes:
        aesgcm = AESGCM(sha256(self.entropy_key).digest())
        return aesgcm.encrypt(nonce, fragment, associated_data=None)

    def fragment(self, message: bytes, redundancy: float = 0.25, inject_noise: bool = True) -> List[Dict]:
        if not message:
            raise FragmentationError("Cannot fragment empty message")

        message_id = uuid.uuid4().hex
        padded_msg = xor_with_entropy_pad(message, self.entropy_key)
        fragments = [padded_msg[i:i + MAX_FRAGMENT_SIZE] for i in range(0, len(padded_msg), MAX_FRAGMENT_SIZE)]
        
        logger.info(f"Original fragment count: {len(fragments)}")
        encoded_fragments = erasure_encode(fragments, redundancy)

        output_packets = []
        for idx, frag in enumerate(encoded_fragments):
            nonce = os.urandom(12)
            encrypted = self._encrypt_fragment(frag, nonce)
            output_packets.append({
                "msg_id": message_id,
                "frag_idx": idx,
                "total": len(encoded_fragments),
                "nonce": nonce.hex(),
                "payload": encrypted.hex()
            })

        if inject_noise:
            output_packets = inject_dummy_packets(output_packets, ratio=0.3)

        random.shuffle(output_packets)
        return output_packets

    def reassemble(self, fragments: List[Dict]) -> Optional[bytes]:
        if not fragments:
            return None

        try:
            fragments_by_idx: Dict[int, bytes] = {}
            total = None
            for packet in fragments:
                try:
                    idx = packet["frag_idx"]
                    total = packet["total"]
                    nonce = bytes.fromhex(packet["nonce"])
                    ciphertext = bytes.fromhex(packet["payload"])
                    decrypted = AESGCM(sha256(self.entropy_key).digest()).decrypt(nonce, ciphertext, associated_data=None)
                    fragments_by_idx[idx] = decrypted
                except Exception as e:
                    logger.warning(f"Decryption failed on fragment {packet.get('frag_idx')}: {e}")
                    continue

            if total is None or len(fragments_by_idx) < int(total * 0.75):
                logger.warning("Not enough fragments to reassemble")
                return None

            ordered = [fragments_by_idx[i] for i in sorted(fragments_by_idx.keys())]
            rejoined = erasure_decode(ordered, total)
            return xor_with_entropy_pad(rejoined, self.entropy_key)
        except Exception as e:
            logger.error(f"Reassembly failed: {e}")
            return None
