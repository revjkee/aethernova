"""
Session Manager - Identity Access Core
Управление пользовательскими сессиями
"""

import asyncio
import secrets
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from loguru import logger


class SessionManager:
    """Менеджер пользовательских сессий"""
    
    def __init__(self, config: Any):
        self.config = config
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self.user_sessions: Dict[str, List[str]] = {}  # user_id -> [session_ids]
        self.session_timeout = timedelta(seconds=config.emergency_session_timeout)
        self.max_sessions_per_user = config.emergency_session_limit
        
        logger.info("🔐 Session Manager инициализирован")
    
    async def create_session(
        self,
        user: Dict[str, Any],
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Создает новую сессию для пользователя
        
        Args:
            user: Данные пользователя
            ip_address: IP адрес клиента
            user_agent: User-Agent клиента
            
        Returns:
            Данные созданной сессии
        """
        user_id = user['user_id']
        
        # Проверка лимита сессий
        if user_id in self.user_sessions:
            if len(self.user_sessions[user_id]) >= self.max_sessions_per_user:
                # Удаление самой старой сессии
                await self._cleanup_oldest_session(user_id)
        
        # Генерация ID сессии
        session_id = secrets.token_urlsafe(32)
        
        # Создание сессии
        session = {
            "session_id": session_id,
            "user_id": user_id,
            "username": user['username'],
            "roles": user['roles'],
            "permissions": user['permissions'],
            "created_at": datetime.now(),
            "expires_at": datetime.now() + self.session_timeout,
            "last_activity": datetime.now(),
            "ip_address": ip_address,
            "user_agent": user_agent,
            "is_active": True,
            "metadata": {}
        }
        
        self.sessions[session_id] = session
        
        # Добавление в список сессий пользователя
        if user_id not in self.user_sessions:
            self.user_sessions[user_id] = []
        self.user_sessions[user_id].append(session_id)
        
        logger.info(f"✅ Сессия создана: {session_id[:16]}... для {user['username']}")
        
        return {
            "session_id": session_id,
            "expires_at": session['expires_at'].isoformat(),
            "created_at": session['created_at'].isoformat()
        }
    
    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Получает данные сессии"""
        session = self.sessions.get(session_id)
        
        if not session:
            return None
        
        # Проверка истечения срока
        if await self._is_session_expired(session_id):
            await self.destroy_session(session_id)
            return None
        
        # Обновление времени активности
        session['last_activity'] = datetime.now()
        
        return session
    
    async def validate_session(self, session_id: str) -> bool:
        """Проверяет валидность сессии"""
        session = await self.get_session(session_id)
        return session is not None and session['is_active']
    
    async def destroy_session(self, session_id: str) -> bool:
        """Уничтожает сессию"""
        if session_id not in self.sessions:
            return False
        
        session = self.sessions[session_id]
        user_id = session['user_id']
        
        # Удаление из списка сессий пользователя
        if user_id in self.user_sessions:
            if session_id in self.user_sessions[user_id]:
                self.user_sessions[user_id].remove(session_id)
            
            # Очистка списка, если пуст
            if not self.user_sessions[user_id]:
                del self.user_sessions[user_id]
        
        # Удаление сессии
        del self.sessions[session_id]
        
        logger.info(f"✅ Сессия уничтожена: {session_id[:16]}...")
        return True
    
    async def destroy_user_sessions(self, user_id: str) -> int:
        """Уничтожает все сессии пользователя"""
        if user_id not in self.user_sessions:
            return 0
        
        session_ids = list(self.user_sessions[user_id])
        destroyed_count = 0
        
        for session_id in session_ids:
            if await self.destroy_session(session_id):
                destroyed_count += 1
        
        logger.info(f"✅ Уничтожено {destroyed_count} сессий пользователя {user_id}")
        return destroyed_count
    
    async def refresh_session(self, session_id: str) -> bool:
        """Обновляет срок действия сессии"""
        session = await self.get_session(session_id)
        
        if not session:
            return False
        
        session['expires_at'] = datetime.now() + self.session_timeout
        session['last_activity'] = datetime.now()
        
        logger.debug(f"🔄 Сессия обновлена: {session_id[:16]}...")
        return True
    
    async def _is_session_expired(self, session_id: str) -> bool:
        """Проверяет, истекла ли сессия"""
        session = self.sessions.get(session_id)
        
        if not session:
            return True
        
        return datetime.now() > session['expires_at']
    
    async def _cleanup_oldest_session(self, user_id: str) -> None:
        """Удаляет самую старую сессию пользователя"""
        if user_id not in self.user_sessions:
            return
        
        session_ids = self.user_sessions[user_id]
        if not session_ids:
            return
        
        # Находим самую старую сессию
        oldest_session_id = None
        oldest_time = datetime.now()
        
        for session_id in session_ids:
            if session_id in self.sessions:
                session = self.sessions[session_id]
                if session['created_at'] < oldest_time:
                    oldest_time = session['created_at']
                    oldest_session_id = session_id
        
        if oldest_session_id:
            await self.destroy_session(oldest_session_id)
            logger.info(f"🗑️ Удалена старая сессия пользователя {user_id}")
    
    async def cleanup_expired_sessions(self) -> int:
        """Очищает истекшие сессии"""
        expired_sessions = []
        
        for session_id, session in self.sessions.items():
            if datetime.now() > session['expires_at']:
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            await self.destroy_session(session_id)
        
        if expired_sessions:
            logger.info(f"🗑️ Очищено {len(expired_sessions)} истекших сессий")
        
        return len(expired_sessions)
    
    async def get_user_sessions(self, user_id: str) -> List[Dict[str, Any]]:
        """Возвращает все активные сессии пользователя"""
        if user_id not in self.user_sessions:
            return []
        
        sessions = []
        for session_id in self.user_sessions[user_id]:
            if session_id in self.sessions:
                session = self.sessions[session_id]
                sessions.append({
                    "session_id": session_id,
                    "created_at": session['created_at'].isoformat(),
                    "expires_at": session['expires_at'].isoformat(),
                    "last_activity": session['last_activity'].isoformat(),
                    "ip_address": session['ip_address'],
                    "user_agent": session['user_agent']
                })
        
        return sessions
    
    async def update_session_metadata(
        self,
        session_id: str,
        metadata: Dict[str, Any]
    ) -> bool:
        """Обновляет метаданные сессии"""
        session = await self.get_session(session_id)
        
        if not session:
            return False
        
        session['metadata'].update(metadata)
        return True
    
    def get_active_sessions_count(self) -> int:
        """Возвращает количество активных сессий"""
        return len(self.sessions)
    
    def get_stats(self) -> Dict[str, Any]:
        """Возвращает статистику сессий"""
        total_sessions = len(self.sessions)
        active_users = len(self.user_sessions)
        
        # Подсчет истекших сессий
        expired_count = 0
        for session in self.sessions.values():
            if datetime.now() > session['expires_at']:
                expired_count += 1
        
        return {
            "total_sessions": total_sessions,
            "active_users": active_users,
            "expired_sessions": expired_count,
            "active_sessions": total_sessions - expired_count,
            "avg_sessions_per_user": total_sessions / active_users if active_users > 0 else 0
        }
