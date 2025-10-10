"""
Identity Access Core - Source Modules
Модули аутентификации, авторизации и управления сессиями
"""

from .authentication import AuthenticationService
from .authorization import AuthorizationEngine, Permission
from .session_manager import SessionManager

__all__ = [
    "AuthenticationService",
    "AuthorizationEngine",
    "Permission",
    "SessionManager"
]
