# /security/mfa-guard/totp.py
import time
import hmac
import hashlib
import base64
import struct
from typing import Optional


class TOTP:
    """
    Класс для генерации и проверки TOTP (Time-based One-Time Password) по RFC 6238.
    Используется для двухфакторной аутентификации.
    """

    def __init__(self, secret: str, digits: int = 6, interval: int = 30, digest=hashlib.sha1):
        """
        :param secret: Секрет в base32-формате
        :param digits: Количество цифр кода (обычно 6)
        :param interval: Интервал жизни кода в секундах (обычно 30)
        :param digest: Хеш-функция (sha1 по умолчанию)
        """
        self.secret = secret
        self.digits = digits
        self.interval = interval
        self.digest = digest

    def _decode_secret(self) -> bytes:
        """Декодирует base32 секрет."""
        padding = '=' * ((8 - len(self.secret) % 8) % 8)  # padding для base32
        return base64.b32decode(self.secret.upper() + padding)

    def _generate_otp(self, input: int) -> str:
        """Генерирует OTP на основе входного числа."""
        key = self._decode_secret()
        msg = struct.pack(">Q", input)
        hmac_digest = hmac.new(key, msg, self.digest).digest()
        offset = hmac_digest[-1] & 0x0F
        code = (struct.unpack(">I", hmac_digest[offset:offset+4])[0] & 0x7FFFFFFF) % (10 ** self.digits)
        return str(code).zfill(self.digits)

    def generate(self, for_time: Optional[int] = None) -> str:
        """
        Генерирует TOTP для заданного времени (по умолчанию текущее).
        :param for_time: Время в секундах Unix Epoch
        :return: Строка OTP
        """
        if for_time is None:
            for_time = int(time.time())
        counter = int(for_time / self.interval)
        return self._generate_otp(counter)

    def verify(self, otp: str, at_time: Optional[int] = None, window: int = 1) -> bool:
        """
        Проверяет OTP, учитывая окно ±window интервалов для синхронизации часов.
        :param otp: Код для проверки
        :param at_time: Время, для которого проверяется код (по умолчанию текущее)
        :param window: Кол-во интервалов по обе стороны для проверки (по умолчанию 1)
        :return: True если код валиден, иначе False
        """
        if at_time is None:
            at_time = int(time.time())
        counter = int(at_time / self.interval)
        for offset in range(-window, window + 1):
            if self._generate_otp(counter + offset) == otp:
                return True
        return False
