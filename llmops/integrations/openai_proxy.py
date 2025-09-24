import asyncio
import time
from typing import Optional, Dict, Any, List
import httpx
from pydantic import BaseModel, Field, validator
import logging
from starlette.concurrency import run_in_threadpool
from llmops.utils.tracing import trace_async
from llmops.config import settings

logger = logging.getLogger(__name__)
TIMEOUT = httpx.Timeout(60.0, connect=5.0)

# Поддержка нескольких провайдеров (можно расширить под Anthropic, Mistral и др.)
class LLMProvider(str):
    OPENAI = "openai"
    AZURE_OPENAI = "azure_openai"

# Входная схема запроса
class OpenAIChatMessage(BaseModel):
    role: str
    content: str

class OpenAIChatRequest(BaseModel):
    model: str
    messages: List[OpenAIChatMessage]
    temperature: Optional[float] = 0.7
    max_tokens: Optional[int] = 1024
    stream: Optional[bool] = False
    user: Optional[str] = None
    provider: Optional[LLMProvider] = LLMProvider.OPENAI
    stop: Optional[List[str]] = None
    presence_penalty: Optional[float] = None
    frequency_penalty: Optional[float] = None
    top_p: Optional[float] = 1.0

    @validator("temperature")
    def validate_temperature(cls, v):
        if not 0 <= v <= 2:
            raise ValueError("Temperature must be between 0 and 2")
        return v

# Ответ в режиме потока
class OpenAIStreamingChunk(BaseModel):
    content: Optional[str] = None
    finish_reason: Optional[str] = None

# Ответ в обычном режиме
class OpenAIChatResponse(BaseModel):
    content: str
    usage: Optional[Dict[str, int]] = None
    finish_reason: Optional[str] = None

@trace_async("llm.openai_proxy.chat_completion")
async def chat_completion(request: OpenAIChatRequest) -> OpenAIChatResponse:
    if request.provider == LLMProvider.AZURE_OPENAI:
        return await _azure_openai_chat(request)
    return await _openai_chat(request)

async def _openai_chat(request: OpenAIChatRequest) -> OpenAIChatResponse:
    url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {settings.openai_api_key}",
        "Content-Type": "application/json"
    }

    payload = request.dict(exclude_none=True)
    logger.debug(f"Sending OpenAI request: {payload}")

    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        response = await client.post(url, json=payload, headers=headers)
        response.raise_for_status()
        data = response.json()

    logger.debug(f"Received OpenAI response: {data}")

    content = data["choices"][0]["message"]["content"]
    usage = data.get("usage")
    finish_reason = data["choices"][0].get("finish_reason")

    return OpenAIChatResponse(content=content, usage=usage, finish_reason=finish_reason)

async def _azure_openai_chat(request: OpenAIChatRequest) -> OpenAIChatResponse:
    # Пример реализации Azure-совместимого API-запроса
    deployment = settings.azure_openai_deployment
    url = f"{settings.azure_openai_endpoint}/openai/deployments/{deployment}/chat/completions?api-version=2023-05-15"

    headers = {
        "api-key": settings.azure_openai_api_key,
        "Content-Type": "application/json"
    }

    payload = request.dict(exclude_none=True)
    payload["model"] = None  # Azure использует deployment вместо model
    logger.debug(f"Sending Azure OpenAI request: {payload}")

    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        response = await client.post(url, json=payload, headers=headers)
        response.raise_for_status()
        data = response.json()

    logger.debug(f"Received Azure OpenAI response: {data}")

    content = data["choices"][0]["message"]["content"]
    usage = data.get("usage")
    finish_reason = data["choices"][0].get("finish_reason")

    return OpenAIChatResponse(content=content, usage=usage, finish_reason=finish_reason)
