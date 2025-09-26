from __future__ import annotations

import base64
import hmac
import logging
import os
import re
import secrets
import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple, Literal

try:
    from argon2 import PasswordHasher as _Argon2Hasher
    from argon2.low_level import Type as Argon2Type
    _HAS_ARGON2 = True
except Exception:
    _HAS_ARGON2 = False

try:
    import bcrypt as _bcrypt
    _HAS_BCRYPT = True
except Exception:
    _HAS_BCRYPT = False


logger = logging.getLogger(__name__)


class HashAlgo(str, Enum):
    ARGON2ID = "argon2id"
    BCRYPT = "bcrypt"


@dataclass(frozen=True)
class Argon2Params:
    time_cost: int = int(os.getenv("PW_ARGON2_TIME_COST", "3"))
    memory_cost_kib: int = int(os.getenv("PW_ARGON2_MEMORY_KIB", "65536"))  # 64 MiB
    parallelism: int = int(os.getenv("PW_ARGON2_PARALLELISM", "2"))
    hash_len: int = int(os.getenv("PW_ARGON2_HASH_LEN", "32"))
    salt_len: int = int(os.getenv("PW_ARGON2_SALT_LEN", "16"))


@dataclass(frozen=True)
class BCryptParams:
    rounds: int = int(os.getenv("PW_BCRYPT_ROUNDS", "12"))  # cost


@dataclass(frozen=True)
class PasswordHasherConfig:
    algo: HashAlgo = HashAlgo(os.getenv("PW_ALGO", HashAlgo.ARGON2ID.value))
    pepper_env: str = os.getenv("PW_PEPPER_ENV", "PW_PEPPER")
    allow_rehash_on_verify: bool = os.getenv("PW_ALLOW_REHASH", "1") == "1"
    allow_migrate_from: Tuple[HashAlgo, ...] = tuple(
        a.strip() for a in os.getenv("PW_MIGRATE_FROM", "bcrypt").split(",") if a.strip()
    ) or tuple()
    argon2: Argon2Params = Argon2Params()
    bcrypt: BCryptParams = BCryptParams()
    # Префиксы формата хранения
    prefix_argon2: str = "$a2id$"
    prefix_bcrypt: str = "$2b$"  # штатный bcrypt-префикс


class PasswordHashError(Exception):
    pass


class UnsupportedAlgorithmError(PasswordHashError):
    pass


class VerificationError(PasswordHashError):
    pass


class PepperMissingError(PasswordHashError):
    pass


class PasswordHasher:
    """
    Промышленный утилитарный класс для хэширования и проверки паролей.
    Особенности:
      - Argon2id по умолчанию; поддержан bcrypt для миграций/совместимости.
      - «Перец» (pepper) через HMAC-BLAKE2b. Ключ хранится в переменной окружения.
      - Безопасная проверка в константное время.
      - Автоматическое определение формата и rehash/migrate при verify().
      - Чистые синхронные и асинхронные API.

    Хранимый формат:
      - Argon2id:  "$a2id$" + исходная строка argon2-cffi
      - bcrypt:    стандартный формат "$2b$..." (без доп. префикса)
    """

    _ARGON2_RE = re.compile(r"^\$argon2id\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$")
    _BCRYPT_RE = re.compile(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$")

    def __init__(self, config: Optional[PasswordHasherConfig] = None) -> None:
        self.cfg = config or PasswordHasherConfig()

        # Инициализация бекендов
        self._argon2_hasher: Optional[_Argon2Hasher] = None
        if self.cfg.algo == HashAlgo.ARGON2ID or HashAlgo.ARGON2ID in self.cfg.allow_migrate_from:
            if not _HAS_ARGON2:
                if self.cfg.algo == HashAlgo.ARGON2ID:
                    raise UnsupportedAlgorithmError("argon2-cffi не установлен")
            else:
                self._argon2_hasher = _Argon2Hasher(
                    time_cost=self.cfg.argon2.time_cost,
                    memory_cost=self.cfg.argon2.memory_cost_kib,
                    parallelism=self.cfg.argon2.parallelism,
                    hash_len=self.cfg.argon2.hash_len,
                    salt_len=self.cfg.argon2.salt_len,
                    type=Argon2Type.ID,
                )

        self._bcrypt_available = _HAS_BCRYPT

        if self.cfg.algo == HashAlgo.BCRYPT and not self._bcrypt_available:
            raise UnsupportedAlgorithmError("bcrypt не установлен")

        # Проверка наличия перца, если требуется
        self._pepper_key = os.getenv(self.cfg.pepper_env, "")
        if not self._pepper_key:
            # Можно разрешить работу без перца, если явно указано PW_PEPPER_REQUIRED=0
            if os.getenv("PW_PEPPER_REQUIRED", "1") == "1":
                raise PepperMissingError(
                    f"Секрет перца не найден в переменной окружения {self.cfg.pepper_env}"
                )

    # ---------------------------- ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ ----------------------------

    def _pepper(self, password: str) -> bytes:
        """
        Возвращает HMAC-BLAKE2b(password, pepper) как байты.
        Если перец не задан и разрешено, возвращает UTF-8 байты пароля.
        """
        pwd_bytes = password.encode("utf-8")
        if not self._pepper_key:
            return pwd_bytes
        key = self._pepper_key.encode("utf-8")
        # BLAKE2b в режиме HMAC-подобного использования через key
        return hashlib.blake2b(pwd_bytes, key=key, digest_size=64).digest()

    @staticmethod
    def _b64(data: bytes) -> str:
        return base64.b64encode(data).decode("ascii")

    # ---------------------------- ПУБЛИЧНЫЕ МЕТОДЫ ----------------------------

    def hash(self, password: str) -> str:
        """
        Хэширует пароль согласно текущей конфигурации.
        """
        if self.cfg.algo == HashAlgo.ARGON2ID:
            if not self._argon2_hasher:
                raise UnsupportedAlgorithmError("Argon2 недоступен")
            # argon2-cffi ожидает текст, поэтому кодируем перчёный пароль в base64
            peppered = self._b64(self._pepper(password))
            arg = self._argon2_hasher.hash(peppered)
            return f"{self.cfg.prefix_argon2}{arg}"

        elif self.cfg.algo == HashAlgo.BCRYPT:
            if not self._bcrypt_available:
                raise UnsupportedAlgorithmError("bcrypt недоступен")
            peppered = self._pepper(password)
            salt = _bcrypt.gensalt(rounds=self.cfg.bcrypt.rounds)
            digest = _bcrypt.hashpw(peppered, salt).decode("utf-8")
            return digest

        else:
            raise UnsupportedAlgorithmError(f"Неизвестный алгоритм: {self.cfg.algo}")

    def verify(self, password: str, stored_hash: str) -> Tuple[bool, bool]:
        """
        Проверяет пароль против сохранённого хеша.
        Возвращает (is_valid, needs_rehash_or_migrate).
        """
        try:
            if stored_hash.startswith(self.cfg.prefix_argon2):
                if not self._argon2_hasher:
                    raise UnsupportedAlgorithmError("Argon2 недоступен для проверки")
                arg_line = stored_hash[len(self.cfg.prefix_argon2):]
                if not self._ARGON2_RE.match(arg_line):
                    raise VerificationError("Неверный формат Argon2id")
                peppered = self._b64(self._pepper(password))
                self._argon2_hasher.verify(arg_line, peppered)
                needs = self._argon2_hasher.check_needs_rehash(arg_line)
                return True, bool(needs)

            if self._BCRYPT_RE.match(stored_hash):
                if not self._bcrypt_available:
                    raise UnsupportedAlgorithmError("bcrypt недоступен для проверки")
                peppered = self._pepper(password)
                is_valid = _bcrypt.checkpw(peppered, stored_hash.encode("utf-8"))
                needs = False
                # Если текущая схема = argon2id и миграция с bcrypt разрешена — пометить для миграции
                if is_valid and self.cfg.algo == HashAlgo.ARGON2ID and HashAlgo.BCRYPT in self.cfg.allow_migrate_from:
                    needs = True
                return bool(is_valid), needs

            raise VerificationError("Неизвестный/неподдерживаемый формат хеша")

        except Exception as exc:
            # Не раскрываем детали, но логируем для диагностики
            logger.debug("Password verify failed: %r", exc)
            return False, False

    def needs_rehash(self, stored_hash: str) -> bool:
        """
        Явная проверка необходимости rehash без валидации пароля.
        """
        if stored_hash.startswith(self.cfg.prefix_argon2):
            if not self._argon2_hasher:
                return False
            arg_line = stored_hash[len(self.cfg.prefix_argon2):]
            return bool(self._argon2_hasher.check_needs_rehash(arg_line))
        # Для bcrypt критерий — политика организации (например, перевод на Argon2id)
        if self._BCRYPT_RE.match(stored_hash) and self.cfg.algo == HashAlgo.ARGON2ID:
            return HashAlgo.BCRYPT in self.cfg.allow_migrate_from
        return False

    # ---------------------------- УТИЛИТЫ ДЛЯ МИГРАЦИИ ----------------------------

    def upgrade_if_needed(self, password: str, stored_hash: str) -> Optional[str]:
        """
        Если verify() прошла и требуется миграция/rehash, вернёт новый хеш.
        Иначе None.
        """
        valid, needs = self.verify(password, stored_hash)
        if not valid or not needs or not self.cfg.allow_rehash_on_verify:
            return None
        return self.hash(password)

    # ---------------------------- АСИНХРОННЫЕ ОБЕРТКИ ----------------------------

    async def a_hash(self, password: str) -> str:
        import asyncio
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.hash, password)

    async def a_verify(self, password: str, stored_hash: str) -> Tuple[bool, bool]:
        import asyncio
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.verify, password, stored_hash)

    async def a_needs_rehash(self, stored_hash: str) -> bool:
        import asyncio
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.needs_rehash, stored_hash)

    async def a_upgrade_if_needed(self, password: str, stored_hash: str) -> Optional[str]:
        import asyncio
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.upgrade_if_needed, password, stored_hash)


# ---------------------------- ПРИМЕР БЕЗОПАСНОГО ИСПОЛЬЗОВАНИЯ (для интеграции) ----------------------------
# from backend.src.utils.password_hasher import PasswordHasher
# hasher = PasswordHasher()
# user.password_hash = hasher.hash(plain_password)
# ok, needs = hasher.verify(plain_password, user.password_hash)
# if ok and needs:
#     user.password_hash = hasher.hash(plain_password)
#
# В продакшн-коде храните PW_PEPPER в безопасном хранилище секретов.
