"""
Authentication Service - Identity Access Core
Модуль аутентификации пользователей
"""

import asyncio
import hashlib
import secrets
import jwt
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from loguru import logger
import bcrypt


class AuthenticationService:
    """Сервис аутентификации пользователей"""
    
    def __init__(self, config: Any):
        self.config = config
        self.users_db: Dict[str, Dict[str, Any]] = {}
        self.failed_attempts: Dict[str, int] = {}
        self.locked_accounts: Dict[str, datetime] = {}
        self.jwt_secret = config.emergency_encryption_key
        self.max_failed_attempts = 5
        self.lockout_duration = timedelta(minutes=15)
        
        if config.emergency_admin_enabled:
            self._create_emergency_admin()
        
        logger.info("🔐 Authentication Service инициализирован")
    
    def _create_emergency_admin(self) -> None:
        """Создает экстренного администратора"""
        password = self.config.emergency_admin_password
        if password is None:
            raise RuntimeError("Emergency admin password was not validated")

        password_hash = bcrypt.hashpw(
            password.encode('utf-8'),
            bcrypt.gensalt()
        )
        
        self.users_db["emergency_admin"] = {
            "user_id": "emergency_admin",
            "username": "emergency_admin",
            "password_hash": password_hash.decode('utf-8'),
            "roles": ["admin", "emergency", "superuser"],
            "permissions": ["*"],
            "email": "emergency@aethernova.system",
            "mfa_enabled": False,
            "created_at": datetime.now().isoformat(),
            "last_login": None,
            "account_status": "active"
        }
        
        logger.critical("🚨 Экстренный администратор создан")
    
    async def authenticate(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """
        Аутентифицирует пользователя
        
        Args:
            username: Имя пользователя
            password: Пароль
            
        Returns:
            Данные пользователя или None при ошибке
        """
        # Проверка блокировки аккаунта
        if await self._is_account_locked(username):
            logger.warning(f"⚠️ Попытка входа в заблокированный аккаунт: {username}")
            return None
        
        # Получение пользователя
        user = self.users_db.get(username)
        if not user:
            await self._record_failed_attempt(username)
            logger.warning(f"⚠️ Пользователь не найден: {username}")
            return None
        
        # Проверка пароля
        if not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            await self._record_failed_attempt(username)
            logger.warning(f"⚠️ Неверный пароль для пользователя: {username}")
            return None
        
        # Успешная аутентификация
        await self._reset_failed_attempts(username)
        user['last_login'] = datetime.now().isoformat()
        
        logger.info(f"✅ Успешная аутентификация: {username}")
        return user
    
    async def create_user(
        self,
        username: str,
        password: str,
        email: str,
        roles: List[str] = None,
        permissions: List[str] = None
    ) -> Dict[str, Any]:
        """Создает нового пользователя"""
        if username in self.users_db:
            raise ValueError(f"Пользователь {username} уже существует")
        
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        user = {
            "user_id": secrets.token_hex(16),
            "username": username,
            "password_hash": password_hash.decode('utf-8'),
            "roles": roles or ["user"],
            "permissions": permissions or ["read"],
            "email": email,
            "mfa_enabled": False,
            "created_at": datetime.now().isoformat(),
            "last_login": None,
            "account_status": "active"
        }
        
        self.users_db[username] = user
        logger.info(f"✅ Пользователь создан: {username}")
        
        return {k: v for k, v in user.items() if k != 'password_hash'}
    
    async def generate_token(self, user: Dict[str, Any], expires_in: int = 3600) -> str:
        """Генерирует JWT токен для пользователя"""
        payload = {
            "user_id": user['user_id'],
            "username": user['username'],
            "roles": user['roles'],
            "permissions": user['permissions'],
            "exp": datetime.utcnow() + timedelta(seconds=expires_in),
            "iat": datetime.utcnow()
        }
        
        token = jwt.encode(payload, self.jwt_secret, algorithm='HS256')
        logger.debug(f"🎫 JWT токен сгенерирован для {user['username']}")
        
        return token
    
    async def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Проверяет JWT токен"""
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=['HS256'])
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("⚠️ Токен истек")
            return None
        except jwt.InvalidTokenError:
            logger.warning("⚠️ Недействительный токен")
            return None
    
    async def _is_account_locked(self, username: str) -> bool:
        """Проверяет, заблокирован ли аккаунт"""
        if username in self.locked_accounts:
            lock_time = self.locked_accounts[username]
            if datetime.now() < lock_time + self.lockout_duration:
                return True
            else:
                # Разблокировка по истечении времени
                del self.locked_accounts[username]
                self.failed_attempts[username] = 0
        return False
    
    async def _record_failed_attempt(self, username: str) -> None:
        """Записывает неудачную попытку входа"""
        self.failed_attempts[username] = self.failed_attempts.get(username, 0) + 1
        
        if self.failed_attempts[username] >= self.max_failed_attempts:
            self.locked_accounts[username] = datetime.now()
            logger.warning(f"🔒 Аккаунт заблокирован: {username}")
    
    async def _reset_failed_attempts(self, username: str) -> None:
        """Сбрасывает счетчик неудачных попыток"""
        if username in self.failed_attempts:
            del self.failed_attempts[username]
    
    async def change_password(
        self,
        username: str,
        old_password: str,
        new_password: str
    ) -> bool:
        """Изменяет пароль пользователя"""
        user = await self.authenticate(username, old_password)
        if not user:
            return False
        
        new_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        self.users_db[username]['password_hash'] = new_hash.decode('utf-8')
        
        logger.info(f"✅ Пароль изменен для пользователя: {username}")
        return True
    
    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        """Получает информацию о пользователе"""
        user = self.users_db.get(username)
        if user:
            return {k: v for k, v in user.items() if k != 'password_hash'}
        return None
    
    def list_users(self) -> List[Dict[str, Any]]:
        """Возвращает список всех пользователей"""
        return [
            {k: v for k, v in user.items() if k != 'password_hash'}
            for user in self.users_db.values()
        ]
    
    async def delete_user(self, username: str) -> bool:
        """Удаляет пользователя"""
        if username == "emergency_admin":
            logger.error("❌ Невозможно удалить экстренного администратора")
            return False
        
        if username in self.users_db:
            del self.users_db[username]
            logger.info(f"✅ Пользователь удален: {username}")
            return True
        
        return False
    
    def get_stats(self) -> Dict[str, Any]:
        """Возвращает статистику аутентификации"""
        return {
            "total_users": len(self.users_db),
            "locked_accounts": len(self.locked_accounts),
            "failed_attempts_tracked": len(self.failed_attempts),
            "active_users": sum(1 for u in self.users_db.values() if u['account_status'] == 'active')
        }
