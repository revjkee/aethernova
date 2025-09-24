import time
from typing import Callable
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware

class MFAMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, mfa_service, timeout_seconds: int = 300):
        super().__init__(app)
        self.mfa_service = mfa_service
        self.timeout = timeout_seconds
        self._sessions = {}

    async def dispatch(self, request: Request, call_next: Callable):
        user = await self._get_user_from_request(request)
        if not user:
            return await call_next(request)

        session_key = user.id
        current_time = time.time()

        # Проверка сессии MFA
        if session_key in self._sessions:
            last_verified = self._sessions[session_key]
            if current_time - last_verified < self.timeout:
                return await call_next(request)
            else:
                del self._sessions[session_key]

        # Запрос MFA токена из заголовка
        mfa_token = request.headers.get("X-MFA-Token")
        if not mfa_token:
            raise HTTPException(status_code=401, detail="MFA token missing")

        # Валидация MFA токена
        if not await self.mfa_service.verify_token(user.id, mfa_token):
            raise HTTPException(status_code=403, detail="Invalid MFA token")

        # Обновление времени успешной проверки MFA
        self._sessions[session_key] = current_time

        return await call_next(request)

    async def _get_user_from_request(self, request: Request):
        # Заглушка, нужно интегрировать с системой аутентификации
        if "user" in request.scope:
            return request.scope["user"]
        return None
