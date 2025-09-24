# TeslaAI WebUI Auth Guard v3.5
# Авторизация: Multi-Realm + AI-aware Session Middleware
# Консилиум: 20 агентов и 3 метагенерала

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from jose import JWTError, jwt
import logging
from webui.security.session_manager import validate_session_cookie
from webui.security.login_validator import validate_jwt_token

logger = logging.getLogger("webui.auth_guard")

# Конфигурация токена
SECRET_KEY = "CHANGE_ME_SECRET"  # должен быть безопасно загружен через keyvault
ALGORITHM = "HS256"
ALLOWED_PATHS = ["/login", "/static", "/favicon.ico"]

class AuthGuardMiddleware(BaseHTTPMiddleware):
    """
    Middleware авторизации, поддерживает:
    - JWT токены в заголовках
    - cookie-based сессии (через session_manager)
    - пропуск определённых маршрутов
    """
    async def dispatch(self, request: Request, call_next):
        path = str(request.url.path)

        if any(path.startswith(ap) for ap in ALLOWED_PATHS):
            return await call_next(request)

        token = request.cookies.get("session_token") or self.extract_token(request)

        if not token:
            logger.warning(f"[ACCESS BLOCKED] No token: {path} — {request.client.host}")
            return JSONResponse({"error": "Unauthorized"}, status_code=401)

        try:
            if token.startswith("ey"):  # предположительно JWT
                payload = validate_jwt_token(token, SECRET_KEY, ALGORITHM)
                request.state.user = payload.get("sub")
            else:
                user_id = validate_session_cookie(token)
                request.state.user = user_id
        except JWTError as e:
            logger.warning(f"[JWT Error] {str(e)}")
            return JSONResponse({"error": "Invalid token"}, status_code=403)
        except Exception as e:
            logger.warning(f"[Session Error] {str(e)}")
            return JSONResponse({"error": "Session validation failed"}, status_code=403)

        return await call_next(request)

    def extract_token(self, request: Request) -> str:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            return auth_header[7:]
        return ""
