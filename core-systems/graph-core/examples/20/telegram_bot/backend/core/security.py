import bcrypt
from typing import Union


class Security:
    """
    Класс для безопасной работы с паролями и хешами.
    Использует bcrypt для хеширования и проверки.
    """

    @staticmethod
    def hash_password(password: Union[str, bytes]) -> bytes:
        """
        Хеширует пароль с использованием bcrypt.
        :param password: пароль в str или bytes
        :return: хеш пароля в bytes
        """
        if isinstance(password, str):
            password = password.encode('utf-8')
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password, salt)
        return hashed

    @staticmethod
    def verify_password(password: Union[str, bytes], hashed: bytes) -> bool:
        """
        Проверяет соответствие пароля и хеша.
        :param password: пароль для проверки
        :param hashed: сохранённый хеш
        :return: True если пароль корректный, иначе False
        """
        if isinstance(password, str):
            password = password.encode('utf-8')
        return bcrypt.checkpw(password, hashed)
