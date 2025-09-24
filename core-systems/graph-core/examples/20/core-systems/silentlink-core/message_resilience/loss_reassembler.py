import logging
import threading
from typing import Dict, List, Optional, Tuple
from collections import defaultdict
from hashlib import sha256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from silentlink_core.security.redundancy import erasure_decode
from silentlink_core.crypto.entropy_pad import xor_with_entropy_pad
from silentlink_core.ai.recovery import ai_predict_missing_fragment

logger = logging.getLogger("message_resilience.loss_reassembler")
logging.basicConfig(level=logging.INFO)

class ReassemblyError(Exception):
    pass

class LossResilientReassembler:
    def __init__(self, entropy_key: bytes, ai_assist: bool = True):
        self.entropy_key = entropy_key
        self.ai_assist = ai_assist
        self.fragments_cache: Dict[str, Dict[int, Tuple[bytes, bytes]]] = defaultdict(dict)
        self.total_fragments: Dict[str, int] = {}
        self.lock = threading.Lock()

    def _decrypt_fragment(self, nonce: bytes, ciphertext: bytes) -> Optional[bytes]:
        try:
            aesgcm = AESGCM(sha256(self.entropy_key).digest())
            return aesgcm.decrypt(nonce, ciphertext, associated_data=None)
        except Exception as e:
            logger.debug(f"Decryption failed: {e}")
            return None

    def submit_fragment(self, packet: Dict) -> Optional[bytes]:
        with self.lock:
            msg_id = packet.get("msg_id")
            frag_idx = packet.get("frag_idx")
            total = packet.get("total")
            nonce = bytes.fromhex(packet["nonce"])
            ciphertext = bytes.fromhex(packet["payload"])

            if not msg_id or frag_idx is None or total is None:
                logger.warning("Malformed packet metadata")
                return None

            decrypted = self._decrypt_fragment(nonce, ciphertext)
            if decrypted is None:
                logger.warning(f"Failed to decrypt fragment {frag_idx}")
                return None

            self.total_fragments[msg_id] = total
            self.fragments_cache[msg_id][frag_idx] = (nonce, decrypted)

            if self._is_ready(msg_id):
                logger.info(f"Attempting full reassembly for msg_id={msg_id}")
                return self._reconstruct(msg_id)

        return None

    def _is_ready(self, msg_id: str) -> bool:
        if msg_id not in self.total_fragments:
            return False
        received = len(self.fragments_cache[msg_id])
        required = int(self.total_fragments[msg_id] * 0.65)
        return received >= required

    def _reconstruct(self, msg_id: str) -> Optional[bytes]:
        total = self.total_fragments.get(msg_id)
        if total is None:
            raise ReassemblyError("Unknown message ID")

        fragments_by_idx = self.fragments_cache[msg_id]
        ordered = []

        for i in range(total):
            if i in fragments_by_idx:
                ordered.append(fragments_by_idx[i][1])
            elif self.ai_assist:
                predicted = ai_predict_missing_fragment(fragments_by_idx, i, total)
                if predicted:
                    ordered.append(predicted)
                else:
                    logger.warning(f"AI failed to reconstruct fragment {i}")
                    return None
            else:
                logger.warning(f"Missing fragment {i} with no AI assistance")
                return None

        try:
            full_data = erasure_decode(ordered, total)
            return xor_with_entropy_pad(full_data, self.entropy_key)
        except Exception as e:
            logger.error(f"Final reassembly failed: {e}")
            return None

    def clear_message(self, msg_id: str) -> None:
        with self.lock:
            self.fragments_cache.pop(msg_id, None)
            self.total_fragments.pop(msg_id, None)
