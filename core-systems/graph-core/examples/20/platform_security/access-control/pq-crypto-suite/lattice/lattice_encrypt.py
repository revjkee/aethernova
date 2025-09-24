# lattice_encrypt.py
# Реализация базового шифрования на решётках (например, упрощённый вариант Kyber или NTRU)
# Включает генерацию ключей, шифрование и дешифрование

import os
from hashlib import sha3_256
from secrets import token_bytes

# Параметры для упрощённого примера (должны быть заменены на реальные параметры PQC библиотеки)
PARAMS = {
    "n": 256,       # размерность решётки
    "q": 3329       # модуль
}

def gen_keypair():
    """
    Генерирует публичный и приватный ключи (упрощённо)
    Возвращает (public_key, secret_key)
    """
    # Секретный ключ — случайный вектор в Z_q^n
    sk = [int.from_bytes(token_bytes(2), 'little') % PARAMS['q'] for _ in range(PARAMS['n'])]
    # Публичный ключ — тоже случайный вектор (для демонстрации)
    pk = [int.from_bytes(token_bytes(2), 'little') % PARAMS['q'] for _ in range(PARAMS['n'])]
    return pk, sk

def encrypt(pk, message: bytes) -> list:
    """
    Упрощённое шифрование сообщения (байты переводятся в элементы решётки)
    Возвращает список целых чисел - шифротекст
    """
    # Для простоты берем первые n байт сообщения, или дополняем нулями
    msg_ints = list(message[:PARAMS['n']])
    if len(msg_ints) < PARAMS['n']:
        msg_ints += [0] * (PARAMS['n'] - len(msg_ints))

    ciphertext = []
    for i in range(PARAMS['n']):
        # Шифротекст: (pk[i] + msg_ints[i]) mod q
        c = (pk[i] + msg_ints[i]) % PARAMS['q']
        ciphertext.append(c)
    return ciphertext

def decrypt(sk, ciphertext: list) -> bytes:
    """
    Дешифрование шифротекста
    Возвращает исходное сообщение в байтах
    """
    message_ints = []
    for i in range(PARAMS['n']):
        # Восстановление сообщения: (ciphertext[i] - sk[i]) mod q
        m = (ciphertext[i] - sk[i]) % PARAMS['q']
        # Ограничим байт (0-255)
        m = m if m < 256 else 0
        message_ints.append(m)
    return bytes(message_ints)

def hash_message(message: bytes) -> bytes:
    """
    Хеширование сообщения для дополнительной безопасности
    """
    return sha3_256(message).digest()

if __name__ == "__main__":
    # Тестирование шифрования/дешифрования
    pk, sk = gen_keypair()
    print("Публичный ключ:", pk[:10], "...")  # Вывод первых 10 элементов
    print("Секретный ключ:", sk[:10], "...")

    msg = b"Тестовое сообщение для шифрования на решётках"
    print("Исходное сообщение:", msg)

    ciphertext = encrypt(pk, msg)
    print("Шифротекст:", ciphertext[:10], "...")

    decrypted = decrypt(sk, ciphertext)
    print("Дешифрованное сообщение:", decrypted.rstrip(b'\x00'))

    # Проверка целостности через хеш
    if hash_message(msg) == hash_message(decrypted.rstrip(b'\x00')):
        print("Шифрование/дешифрование прошло успешно, целостность подтверждена.")
    else:
        print("Ошибка целостности сообщения!")
