import logging
import base64
import hashlib
from io import BytesIO
from typing import Optional, Dict
from datetime import datetime

from PIL import Image
from silentlink_core.crypto.cipher import encrypt_message, decrypt_message
from silentlink_core.security.watermark import embed_watermark, verify_watermark
from silentlink_core.utils.timing import obfuscate_timing
from silentlink_core.core.errors import SteganoChannelError

logger = logging.getLogger("covert.stegano_channel")
logging.basicConfig(level=logging.INFO)

MAX_MESSAGE_SIZE = 4096  # bytes
SIGNATURE_PREFIX = b"SLINK::"

class SteganoChannel:
    def __init__(self, secret_key: bytes):
        self.secret_key = secret_key

    def _hash_payload(self, data: bytes) -> str:
        return hashlib.sha3_256(data).hexdigest()

    def _prepare_message(self, plaintext: str) -> bytes:
        try:
            encrypted = encrypt_message(plaintext.encode(), self.secret_key)
            return SIGNATURE_PREFIX + encrypted
        except Exception as e:
            raise SteganoChannelError("Encryption failed") from e

    def _extract_message(self, data: bytes) -> str:
        try:
            if not data.startswith(SIGNATURE_PREFIX):
                raise SteganoChannelError("Invalid prefix")
            raw = data[len(SIGNATURE_PREFIX):]
            return decrypt_message(raw, self.secret_key).decode()
        except Exception as e:
            raise SteganoChannelError("Decryption failed") from e

    def _encode_to_image(self, message: bytes, cover_image: Image.Image) -> Image.Image:
        try:
            if len(message) > MAX_MESSAGE_SIZE:
                raise SteganoChannelError("Message too large for cover image")

            img = cover_image.convert("RGB")
            pixels = img.load()
            width, height = img.size

            bitstream = ''.join(f"{byte:08b}" for byte in message)
            total_bits = len(bitstream)
            bit_index = 0

            for y in range(height):
                for x in range(width):
                    if bit_index >= total_bits:
                        break
                    r, g, b = pixels[x, y]
                    r = (r & ~1) | int(bitstream[bit_index])
                    bit_index += 1
                    if bit_index < total_bits:
                        g = (g & ~1) | int(bitstream[bit_index])
                        bit_index += 1
                    if bit_index < total_bits:
                        b = (b & ~1) | int(bitstream[bit_index])
                        bit_index += 1
                    pixels[x, y] = (r, g, b)
                if bit_index >= total_bits:
                    break

            return embed_watermark(img, self._hash_payload(message))

        except Exception as e:
            raise SteganoChannelError("Encoding to image failed") from e

    def _decode_from_image(self, image: Image.Image) -> bytes:
        try:
            img = image.convert("RGB")
            pixels = img.load()
            width, height = img.size

            bits = []
            for y in range(height):
                for x in range(width):
                    r, g, b = pixels[x, y]
                    bits.append(str(r & 1))
                    bits.append(str(g & 1))
                    bits.append(str(b & 1))

            bytes_out = bytearray()
            for i in range(0, len(bits), 8):
                byte = bits[i:i+8]
                if len(byte) < 8:
                    break
                byte_val = int(''.join(byte), 2)
                bytes_out.append(byte_val)

            return bytes(bytes_out).rstrip(b'\x00')

        except Exception as e:
            raise SteganoChannelError("Decoding from image failed") from e

    def send_covert_message(self, plaintext: str, cover_image_path: str, output_path: str) -> Dict:
        try:
            cover_img = Image.open(cover_image_path)
            message_bytes = self._prepare_message(plaintext)
            stego_img = self._encode_to_image(message_bytes, cover_img)
            obfuscate_timing()
            stego_img.save(output_path)

            logger.info(f"Covert message embedded and saved to {output_path}")
            return {
                "status": "success",
                "output_path": output_path,
                "hash": self._hash_payload(message_bytes),
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.exception("Failed to send covert message")
            raise SteganoChannelError("Message send failure") from e

    def receive_covert_message(self, stego_image_path: str) -> Dict:
        try:
            img = Image.open(stego_image_path)
            raw_data = self._decode_from_image(img)
            watermark_ok = verify_watermark(img, self._hash_payload(raw_data))
            if not watermark_ok:
                raise SteganoChannelError("Watermark verification failed")

            message = self._extract_message(raw_data)
            logger.info(f"Covert message received and decrypted successfully")

            return {
                "status": "success",
                "message": message,
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.exception("Failed to receive covert message")
            raise SteganoChannelError("Message receive failure") from e
