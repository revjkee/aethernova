# redteam_toolkit/evasion/encryption_packing/aes_encryptor.py
# Промышленная версия AES-шифратора payload-ов с встраиваемым декриптором

import os
import base64
import hashlib
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

BLOCK_SIZE = 16

class AESCipher:
    def __init__(self, key: bytes):
        self.key = hashlib.sha256(key).digest()

    def pad(self, data: bytes) -> bytes:
        padding_len = BLOCK_SIZE - len(data) % BLOCK_SIZE
        return data + bytes([padding_len]) * padding_len

    def unpad(self, data: bytes) -> bytes:
        padding_len = data[-1]
        return data[:-padding_len]

    def encrypt(self, raw: bytes) -> bytes:
        iv = get_random_bytes(BLOCK_SIZE)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(self.pad(raw))
        return iv + encrypted

    def decrypt(self, enc: bytes) -> bytes:
        iv = enc[:BLOCK_SIZE]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(enc[BLOCK_SIZE:])
        return self.unpad(decrypted)

def generate_key(length: int = 32) -> bytes:
    return get_random_bytes(length)

def encrypt_file(input_path: str, output_path: str, key: bytes):
    cipher = AESCipher(key)
    with open(input_path, 'rb') as f:
        raw = f.read()
    enc = cipher.encrypt(raw)
    with open(output_path, 'wb') as f:
        f.write(enc)

def decrypt_file(input_path: str, output_path: str, key: bytes):
    cipher = AESCipher(key)
    with open(input_path, 'rb') as f:
        enc = f.read()
    dec = cipher.decrypt(enc)
    with open(output_path, 'wb') as f:
        f.write(dec)

def export_embedded_decryptor(key: bytes) -> str:
    # Генератор встроенного расшифровщика в C, пригодного для shellcode
    key_hex = ''.join(f"\\x{x:02x}" for x in hashlib.sha256(key).digest())
    decryptor_code = f"""
unsigned char aes_key[32] = "{key_hex}";
// Реализация AES CBC decrypt будет встроена здесь...
"""
    return decryptor_code

# Пример внутреннего генератора ключей
if __name__ == "__main__":
    key = generate_key()
    with open("key.bin", "wb") as f:
        f.write(key)
    encrypt_file("payload.bin", "payload.enc", key)
    print("[+] Payload зашифрован. Ключ сохранён в key.bin.")
