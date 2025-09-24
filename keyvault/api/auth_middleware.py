# keyvault/api/auth_middleware.py

import logging
import jwt
import base64
from typing import Optional, Dict
from fastapi import Request, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from keyvault.config.vault_config_loader import get_auth_config
from keyvault.core.signing_engine import verify_agent_signature
from keyvault.rbac.rbac_evaluator import get_actor_from_claims
from keyvault.utils.context_utils import get_current_context_hash

logger = logging.getLogger("auth_middleware")
logger.setLevel(logging.INFO)

security = HTTPBearer()
config = get_auth_config()

class AuthMiddleware:
    def __init__(self):
        self.jwt_secret = config["jwt_secret"]
        self.jwt_alg = config.get("jwt_alg", "HS256")
        self.allowed_issuers = config.get("allowed_issuers", [])
        self.agent_signature_required = config.get("require_agent_signature", True)

    def decode_jwt(self, token: str) -> Dict:
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_alg])
            if payload.get("iss") not in self.allowed_issuers:
                raise HTTPException(status_code=403, detail="Invalid token issuer")
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token expired")
        except jwt.InvalidTokenError as e:
            raise HTTPException(status_code=403, detail=f"Invalid JWT: {str(e)}")

    def verify_agent_signature_if_required(self, request: Request, payload: Dict):
        if not self.agent_signature_required:
            return

        signature_b64 = request.headers.get("X-Agent-Signature")
        if not signature_b64:
            raise HTTPException(status_code=400, detail="Missing agent signature")

        raw_body = request.scope.get("_body_cache", None)
        if raw_body is None:
            raise HTTPException(status_code=400, detail="Missing request body for signature verification")

        signature = base64.b64decode(signature_b64)

        if not verify_agent_signature(payload["sub"], raw_body, signature):
            raise HTTPException(status_code=403, detail="Invalid agent signature")

    async def authenticate(self, request: Request, credentials: HTTPAuthorizationCredentials) -> Dict:
        token = credentials.credentials
        payload = self.decode_jwt(token)
        actor_id = get_actor_from_claims(payload)

        # Проверка контекста Zero Trust
        client_context_hash = request.headers.get("X-Context-Hash")
        expected_context_hash = get_current_context_hash(actor_id)
        if client_context_hash != expected_context_hash:
            logger.warning(f"Context hash mismatch: {client_context_hash} != {expected_context_hash}")
            raise HTTPException(status_code=403, detail="Invalid session context")

        # Проверка подписи агента
        self.verify_agent_signature_if_required(request, payload)

        return {
            "actor_id": actor_id,
            "claims": payload
        }
