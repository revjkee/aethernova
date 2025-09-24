import jwt
from typing import Callable, Optional
from fastapi import Request, HTTPException
from fastapi.middleware.base import BaseHTTPMiddleware
from fastapi.responses import JSONResponse
from web3.auto import w3
from eth_account.messages import encode_defunct

SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"

class AuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, jwt_secret: str = SECRET_KEY, jwt_algorithm: str = ALGORITHM):
        super().__init__(app)
        self.jwt_secret = jwt_secret
        self.jwt_algorithm = jwt_algorithm

    async def dispatch(self, request: Request, call_next: Callable):
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return JSONResponse(status_code=401, content={"detail": "Authorization header missing"})

        token_type, token = self._parse_auth_header(auth_header)
        if token_type == "Bearer":
            if not self._validate_jwt(token):
                return JSONResponse(status_code=401, content={"detail": "Invalid JWT token"})
        elif token_type == "Session":
            if not self._validate_session(token):
                return JSONResponse(status_code=401, content={"detail": "Invalid Session token"})
        elif token_type == "Web3":
            if not await self._validate_web3_signature(request):
                return JSONResponse(status_code=401, content={"detail": "Invalid Web3 signature"})
        else:
            return JSONResponse(status_code=401, content={"detail": "Unsupported authorization method"})

        response = await call_next(request)
        return response

    def _parse_auth_header(self, header: str) -> tuple[str, Optional[str]]:
        parts = header.split()
        if len(parts) != 2:
            return "", None
        return parts[0], parts[1]

    def _validate_jwt(self, token: str) -> bool:
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_algorithm])
            # Дополнительная проверка payload при необходимости
            return True
        except jwt.PyJWTError:
            return False

    def _validate_session(self, token: str) -> bool:
        # Здесь должна быть логика проверки сессии по токену
        # Например, запрос к базе или кэш для проверки валидности сессии
        # Пока заглушка:
        return token == "valid_session_token"

    async def _validate_web3_signature(self, request: Request) -> bool:
        body = await request.json()
        message = body.get("message")
        signature = body.get("signature")
        address = body.get("address")

        if not message or not signature or not address:
            return False

        try:
            encoded_message = encode_defunct(text=message)
            signer = w3.eth.account.recover_message(encoded_message, signature=signature)
            return signer.lower() == address.lower()
        except Exception:
            return False
