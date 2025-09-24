# gateway/token_metadata_resolver.py

from typing import Optional, Dict, Any
from abc import ABC, abstractmethod
import httpx
from functools import lru_cache
from loguru import logger
from pydantic import BaseModel, AnyHttpUrl, Field

# Интерфейсный контракт для любых провайдеров метаданных токенов
class TokenMetadata(BaseModel):
    token_id: str
    owner_address: str
    metadata: Dict[str, Any]
    access_rights: Optional[Dict[str, Any]] = None
    verified: bool = False


class TokenMetadataProvider(ABC):
    @abstractmethod
    async def resolve(self, token_id: str) -> Optional[TokenMetadata]:
        pass


# Стандартный HTTP-провайдер, работающий с REST-метаданными NFT/DAO
class HTTPTargetProviderConfig(BaseModel):
    base_url: AnyHttpUrl
    verify_ownership: bool = True
    headers: Dict[str, str] = Field(default_factory=dict)


class HTTPTokenMetadataProvider(TokenMetadataProvider):
    def __init__(self, config: HTTPTargetProviderConfig):
        self.config = config

    async def resolve(self, token_id: str) -> Optional[TokenMetadata]:
        try:
            async with httpx.AsyncClient(headers=self.config.headers) as client:
                response = await client.get(f"{self.config.base_url}/tokens/{token_id}")
                response.raise_for_status()
                data = response.json()

                token = TokenMetadata(
                    token_id=token_id,
                    owner_address=data.get("owner", ""),
                    metadata=data.get("metadata", {}),
                    access_rights=data.get("access_rights", {}),
                    verified=self.config.verify_ownership
                )
                return token
        except Exception as e:
            logger.error(f"Failed to resolve metadata for token {token_id}: {e}")
            return None


# Кэшированный резолвер — позволяет переиспользовать уже полученные метаданные
class CachedTokenMetadataResolver:
    def __init__(self, provider: TokenMetadataProvider, max_cache_size: int = 1000):
        self.provider = provider
        self._resolve_cached = lru_cache(maxsize=max_cache_size)(self._resolve_uncached)

    async def resolve(self, token_id: str) -> Optional[TokenMetadata]:
        return await self._resolve_cached(token_id)

    async def _resolve_uncached(self, token_id: str) -> Optional[TokenMetadata]:
        return await self.provider.resolve(token_id)


# Пример инициализации глобального резолвера (заполняется через DI)
global_token_metadata_resolver: Optional[CachedTokenMetadataResolver] = None


def init_token_metadata_resolver(base_url: str, headers: Optional[Dict[str, str]] = None):
    global global_token_metadata_resolver
    provider = HTTPTokenMetadataProvider(
        config=HTTPTargetProviderConfig(base_url=base_url, headers=headers or {})
    )
    global_token_metadata_resolver = CachedTokenMetadataResolver(provider=provider)
    logger.info("Token metadata resolver initialized")
