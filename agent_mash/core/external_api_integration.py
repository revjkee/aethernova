# agent_mash/core/external_api_integration.py

from typing import Dict, Any, List, Optional, Union, Callable, AsyncGenerator
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod
import asyncio
import aiohttp
import json
from datetime import datetime, timedelta
import logging
from collections import deque
import hashlib
import time
from urllib.parse import urljoin, urlparse
import ssl
import certifi

logger = logging.getLogger(__name__)

class APIProtocol(Enum):
    REST = "rest"
    GRAPHQL = "graphql"
    WEBSOCKET = "websocket"
    GRPC = "grpc"

class AuthMethod(Enum):
    NONE = "none"
    API_KEY = "api_key"
    BEARER_TOKEN = "bearer_token"
    BASIC_AUTH = "basic_auth"
    OAUTH2 = "oauth2"
    CUSTOM = "custom"

class RateLimitStrategy(Enum):
    FIXED_WINDOW = "fixed_window"
    SLIDING_WINDOW = "sliding_window"
    TOKEN_BUCKET = "token_bucket"
    EXPONENTIAL_BACKOFF = "exponential_backoff"

@dataclass
class APIEndpoint:
    """Конфигурация API endpoint"""
    name: str
    base_url: str
    protocol: APIProtocol = APIProtocol.REST
    timeout: float = 30.0
    retries: int = 3
    rate_limit: Optional[int] = None  # requests per minute
    rate_limit_strategy: RateLimitStrategy = RateLimitStrategy.FIXED_WINDOW

@dataclass
class AuthConfig:
    """Конфигурация аутентификации"""
    method: AuthMethod
    credentials: Dict[str, str] = field(default_factory=dict)
    token_refresh_endpoint: Optional[str] = None
    token_expires_in: Optional[int] = None  # seconds

@dataclass
class APIRequest:
    """Запрос к API"""
    endpoint: str
    method: str = "GET"
    params: Optional[Dict[str, Any]] = None
    data: Optional[Dict[str, Any]] = None
    headers: Optional[Dict[str, str]] = None
    timeout: Optional[float] = None
    priority: int = 100  # Higher number = higher priority

@dataclass
class APIResponse:
    """Ответ от API"""
    status_code: int
    data: Any
    headers: Dict[str, str]
    response_time: float
    request_id: str
    cached: bool = False

@dataclass
class RateLimitInfo:
    """Информация о лимитах API"""
    limit: int
    remaining: int
    reset_time: datetime
    window_size: int = 60  # seconds

class APICache:
    """Кэш для API ответов"""
    
    def __init__(self, max_size: int = 1000, default_ttl: int = 300):
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.max_size = max_size
        self.default_ttl = default_ttl
        
    def _generate_key(self, request: APIRequest) -> str:
        """Генерация ключа кэша"""
        key_data = {
            "endpoint": request.endpoint,
            "method": request.method,
            "params": request.params,
            "data": request.data
        }
        key_str = json.dumps(key_data, sort_keys=True)
        return hashlib.md5(key_str.encode()).hexdigest()
        
    def get(self, request: APIRequest) -> Optional[Any]:
        """Получение из кэша"""
        key = self._generate_key(request)
        
        if key in self.cache:
            entry = self.cache[key]
            if datetime.utcnow() < entry["expires_at"]:
                return entry["data"]
            else:
                del self.cache[key]
                
        return None
        
    def set(self, request: APIRequest, data: Any, ttl: Optional[int] = None):
        """Сохранение в кэш"""
        if len(self.cache) >= self.max_size:
            # Удаление самых старых записей
            oldest_keys = sorted(
                self.cache.keys(),
                key=lambda k: self.cache[k]["created_at"]
            )[:len(self.cache) - self.max_size + 1]
            
            for key in oldest_keys:
                del self.cache[key]
                
        key = self._generate_key(request)
        ttl = ttl or self.default_ttl
        
        self.cache[key] = {
            "data": data,
            "created_at": datetime.utcnow(),
            "expires_at": datetime.utcnow() + timedelta(seconds=ttl)
        }
        
    def clear(self):
        """Очистка кэша"""
        self.cache.clear()

class RateLimiter:
    """Управление лимитами запросов"""
    
    def __init__(self, limit: int, window_size: int = 60, 
                 strategy: RateLimitStrategy = RateLimitStrategy.FIXED_WINDOW):
        self.limit = limit
        self.window_size = window_size
        self.strategy = strategy
        self.requests = deque()
        self.tokens = limit  # For token bucket
        self.last_refill = time.time()
        
    async def acquire(self) -> bool:
        """Получение разрешения на запрос"""
        if self.strategy == RateLimitStrategy.FIXED_WINDOW:
            return await self._fixed_window_acquire()
        elif self.strategy == RateLimitStrategy.SLIDING_WINDOW:
            return await self._sliding_window_acquire()
        elif self.strategy == RateLimitStrategy.TOKEN_BUCKET:
            return await self._token_bucket_acquire()
        else:
            return True
            
    async def _fixed_window_acquire(self) -> bool:
        """Фиксированное временное окно"""
        now = time.time()
        window_start = now - self.window_size
        
        # Удаление старых запросов
        while self.requests and self.requests[0] < window_start:
            self.requests.popleft()
            
        if len(self.requests) < self.limit:
            self.requests.append(now)
            return True
            
        return False
        
    async def _sliding_window_acquire(self) -> bool:
        """Скользящее временное окно"""
        return await self._fixed_window_acquire()  # Упрощенная версия
        
    async def _token_bucket_acquire(self) -> bool:
        """Алгоритм корзины токенов"""
        now = time.time()
        
        # Пополнение токенов
        time_passed = now - self.last_refill
        tokens_to_add = int(time_passed * (self.limit / self.window_size))
        
        if tokens_to_add > 0:
            self.tokens = min(self.limit, self.tokens + tokens_to_add)
            self.last_refill = now
            
        if self.tokens > 0:
            self.tokens -= 1
            return True
            
        return False
        
    def get_wait_time(self) -> float:
        """Время ожидания до следующего доступного слота"""
        if self.strategy == RateLimitStrategy.TOKEN_BUCKET:
            return self.window_size / self.limit
        else:
            if not self.requests:
                return 0.0
            oldest_request = self.requests[0]
            return max(0.0, oldest_request + self.window_size - time.time())

class APIClient:
    """Клиент для работы с внешними API"""
    
    def __init__(self, endpoint: APIEndpoint, auth: Optional[AuthConfig] = None):
        self.endpoint = endpoint
        self.auth = auth
        self.session: Optional[aiohttp.ClientSession] = None
        self.cache = APICache()
        
        # Rate limiting
        if endpoint.rate_limit:
            self.rate_limiter = RateLimiter(
                limit=endpoint.rate_limit,
                strategy=endpoint.rate_limit_strategy
            )
        else:
            self.rate_limiter = None
            
        # Request queue for priority handling
        self.request_queue = asyncio.PriorityQueue()
        self.queue_processor_task: Optional[asyncio.Task] = None
        
        # Statistics
        self.stats = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "cache_hits": 0,
            "avg_response_time": 0.0,
            "rate_limit_hits": 0
        }
        
    async def __aenter__(self):
        await self.connect()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.disconnect()
        
    async def connect(self):
        """Установка соединения"""
        if self.session is None:
            # SSL context
            ssl_context = ssl.create_default_context(cafile=certifi.where())
            
            connector = aiohttp.TCPConnector(
                ssl=ssl_context,
                limit=100,
                limit_per_host=30,
                ttl_dns_cache=300,
                use_dns_cache=True
            )
            
            timeout = aiohttp.ClientTimeout(total=self.endpoint.timeout)
            
            self.session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers=await self._get_default_headers()
            )
            
            # Запуск обработчика очереди
            self.queue_processor_task = asyncio.create_task(
                self._process_request_queue()
            )
            
    async def disconnect(self):
        """Закрытие соединения"""
        if self.queue_processor_task:
            self.queue_processor_task.cancel()
            try:
                await self.queue_processor_task
            except asyncio.CancelledError:
                pass
                
        if self.session:
            await self.session.close()
            self.session = None
            
    async def _get_default_headers(self) -> Dict[str, str]:
        """Получение заголовков по умолчанию"""
        headers = {
            "User-Agent": "AetherNova-Agent/1.0",
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        
        if self.auth:
            auth_headers = await self._get_auth_headers()
            headers.update(auth_headers)
            
        return headers
        
    async def _get_auth_headers(self) -> Dict[str, str]:
        """Получение заголовков аутентификации"""
        headers = {}
        
        if self.auth.method == AuthMethod.API_KEY:
            api_key = self.auth.credentials.get("api_key")
            key_header = self.auth.credentials.get("header", "X-API-Key")
            if api_key:
                headers[key_header] = api_key
                
        elif self.auth.method == AuthMethod.BEARER_TOKEN:
            token = self.auth.credentials.get("token")
            if token:
                headers["Authorization"] = f"Bearer {token}"
                
        elif self.auth.method == AuthMethod.BASIC_AUTH:
            username = self.auth.credentials.get("username")
            password = self.auth.credentials.get("password")
            if username and password:
                import base64
                credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
                headers["Authorization"] = f"Basic {credentials}"
                
        return headers
        
    async def request(self, request: APIRequest, 
                     cache_ttl: Optional[int] = None,
                     use_cache: bool = True) -> APIResponse:
        """Выполнение запроса"""
        
        # Проверка кэша
        if use_cache and request.method.upper() == "GET":
            cached_response = self.cache.get(request)
            if cached_response:
                self.stats["cache_hits"] += 1
                return APIResponse(
                    status_code=200,
                    data=cached_response,
                    headers={},
                    response_time=0.0,
                    request_id=self._generate_request_id(),
                    cached=True
                )
                
        # Rate limiting
        if self.rate_limiter:
            while not await self.rate_limiter.acquire():
                wait_time = self.rate_limiter.get_wait_time()
                self.stats["rate_limit_hits"] += 1
                logger.warning(f"Rate limit hit, waiting {wait_time:.2f}s")
                await asyncio.sleep(wait_time)
                
        # Выполнение запроса
        return await self._execute_request(request, cache_ttl, use_cache)
        
    async def _execute_request(self, request: APIRequest, 
                              cache_ttl: Optional[int],
                              use_cache: bool) -> APIResponse:
        """Выполнение HTTP запроса"""
        start_time = time.time()
        request_id = self._generate_request_id()
        
        try:
            url = urljoin(self.endpoint.base_url, request.endpoint)
            
            # Подготовка параметров запроса
            kwargs = {
                "method": request.method.upper(),
                "url": url,
                "timeout": request.timeout or self.endpoint.timeout
            }
            
            if request.params:
                kwargs["params"] = request.params
                
            if request.data:
                kwargs["json"] = request.data
                
            if request.headers:
                kwargs["headers"] = request.headers
                
            # Выполнение запроса с retry логикой
            last_exception = None
            
            for attempt in range(self.endpoint.retries + 1):
                try:
                    async with self.session.request(**kwargs) as response:
                        response_time = time.time() - start_time
                        
                        # Чтение ответа
                        try:
                            data = await response.json()
                        except (aiohttp.ContentTypeError, json.JSONDecodeError):
                            data = await response.text()
                            
                        api_response = APIResponse(
                            status_code=response.status,
                            data=data,
                            headers=dict(response.headers),
                            response_time=response_time,
                            request_id=request_id
                        )
                        
                        # Обновление статистики
                        self.stats["total_requests"] += 1
                        
                        if 200 <= response.status < 300:
                            self.stats["successful_requests"] += 1
                            
                            # Сохранение в кэш
                            if (use_cache and request.method.upper() == "GET" and 
                                response.status == 200):
                                self.cache.set(request, data, cache_ttl)
                                
                        else:
                            self.stats["failed_requests"] += 1
                            
                        # Обновление среднего времени ответа
                        old_avg = self.stats["avg_response_time"]
                        total_requests = self.stats["total_requests"]
                        self.stats["avg_response_time"] = (
                            (old_avg * (total_requests - 1) + response_time) / total_requests
                        )
                        
                        return api_response
                        
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    last_exception = e
                    if attempt < self.endpoint.retries:
                        wait_time = 2 ** attempt  # Exponential backoff
                        logger.warning(
                            f"Request failed (attempt {attempt + 1}), "
                            f"retrying in {wait_time}s: {e}"
                        )
                        await asyncio.sleep(wait_time)
                    else:
                        logger.error(f"Request failed after {attempt + 1} attempts: {e}")
                        
            # Все попытки исчерпаны
            self.stats["total_requests"] += 1
            self.stats["failed_requests"] += 1
            
            raise last_exception or Exception("Request failed")
            
        except Exception as e:
            response_time = time.time() - start_time
            
            return APIResponse(
                status_code=500,
                data={"error": str(e)},
                headers={},
                response_time=response_time,
                request_id=request_id
            )
            
    def _generate_request_id(self) -> str:
        """Генерация ID запроса"""
        timestamp = str(int(time.time() * 1000))
        return hashlib.md5(timestamp.encode()).hexdigest()[:8]
        
    async def _process_request_queue(self):
        """Обработка очереди запросов с приоритетами"""
        while True:
            try:
                priority, request_data = await self.request_queue.get()
                request, future = request_data
                
                try:
                    result = await self._execute_request(request, None, True)
                    if not future.cancelled():
                        future.set_result(result)
                except Exception as e:
                    if not future.cancelled():
                        future.set_exception(e)
                        
                self.request_queue.task_done()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in request queue processor: {e}")
                
    async def request_with_priority(self, request: APIRequest, 
                                  priority: int = 100) -> APIResponse:
        """Запрос с приоритетом через очередь"""
        future = asyncio.Future()
        await self.request_queue.put((priority, (request, future)))
        return await future
        
    async def batch_request(self, requests: List[APIRequest], 
                          max_concurrent: int = 10) -> List[APIResponse]:
        """Пакетное выполнение запросов"""
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def execute_with_semaphore(req):
            async with semaphore:
                return await self.request(req)
                
        tasks = [execute_with_semaphore(req) for req in requests]
        return await asyncio.gather(*tasks, return_exceptions=True)
        
    def get_stats(self) -> Dict[str, Any]:
        """Получение статистики"""
        return dict(self.stats)
        
    async def health_check(self) -> bool:
        """Проверка здоровья API"""
        try:
            health_request = APIRequest(
                endpoint="/health",  # Стандартный endpoint
                method="GET",
                timeout=5.0
            )
            
            response = await self.request(health_request, use_cache=False)
            return 200 <= response.status_code < 300
            
        except Exception:
            return False

class ExternalAPIManager:
    """Менеджер для управления множественными внешними API"""
    
    def __init__(self):
        self.clients: Dict[str, APIClient] = {}
        self.circuit_breakers: Dict[str, Dict[str, Any]] = {}
        self.global_stats = {
            "total_apis": 0,
            "healthy_apis": 0,
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0
        }
        
    async def register_api(self, name: str, endpoint: APIEndpoint, 
                          auth: Optional[AuthConfig] = None) -> bool:
        """Регистрация нового API"""
        try:
            client = APIClient(endpoint, auth)
            await client.connect()
            
            self.clients[name] = client
            self.circuit_breakers[name] = {
                "state": "closed",  # closed, open, half-open
                "failure_count": 0,
                "last_failure": None,
                "failure_threshold": 5,
                "timeout": 60  # seconds
            }
            
            self.global_stats["total_apis"] += 1
            logger.info(f"API '{name}' registered successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to register API '{name}': {e}")
            return False
            
    async def unregister_api(self, name: str) -> bool:
        """Отмена регистрации API"""
        if name in self.clients:
            await self.clients[name].disconnect()
            del self.clients[name]
            
            if name in self.circuit_breakers:
                del self.circuit_breakers[name]
                
            self.global_stats["total_apis"] -= 1
            logger.info(f"API '{name}' unregistered")
            return True
            
        return False
        
    async def call_api(self, api_name: str, request: APIRequest) -> APIResponse:
        """Вызов API с circuit breaker защитой"""
        if api_name not in self.clients:
            raise ValueError(f"API '{api_name}' not registered")
            
        # Проверка circuit breaker
        if not await self._check_circuit_breaker(api_name):
            return APIResponse(
                status_code=503,
                data={"error": "Service temporarily unavailable (circuit breaker open)"},
                headers={},
                response_time=0.0,
                request_id="circuit_breaker"
            )
            
        client = self.clients[api_name]
        
        try:
            response = await client.request(request)
            
            # Обновление circuit breaker при успехе
            if 200 <= response.status_code < 300:
                await self._record_success(api_name)
                self.global_stats["successful_requests"] += 1
            else:
                await self._record_failure(api_name)
                self.global_stats["failed_requests"] += 1
                
            self.global_stats["total_requests"] += 1
            return response
            
        except Exception as e:
            await self._record_failure(api_name)
            self.global_stats["failed_requests"] += 1
            self.global_stats["total_requests"] += 1
            
            logger.error(f"API call to '{api_name}' failed: {e}")
            return APIResponse(
                status_code=500,
                data={"error": str(e)},
                headers={},
                response_time=0.0,
                request_id="error"
            )
            
    async def _check_circuit_breaker(self, api_name: str) -> bool:
        """Проверка состояния circuit breaker"""
        cb = self.circuit_breakers[api_name]
        
        if cb["state"] == "open":
            # Проверка таймаута
            if (cb["last_failure"] and 
                datetime.utcnow() - cb["last_failure"] > 
                timedelta(seconds=cb["timeout"])):
                cb["state"] = "half-open"
                cb["failure_count"] = 0
                logger.info(f"Circuit breaker for '{api_name}' moved to half-open")
                return True
            return False
            
        return True
        
    async def _record_success(self, api_name: str):
        """Запись успешного вызова"""
        cb = self.circuit_breakers[api_name]
        
        if cb["state"] == "half-open":
            cb["state"] = "closed"
            cb["failure_count"] = 0
            logger.info(f"Circuit breaker for '{api_name}' closed")
        elif cb["state"] == "closed":
            cb["failure_count"] = max(0, cb["failure_count"] - 1)
            
    async def _record_failure(self, api_name: str):
        """Запись неудачного вызова"""
        cb = self.circuit_breakers[api_name]
        cb["failure_count"] += 1
        cb["last_failure"] = datetime.utcnow()
        
        if (cb["state"] in ["closed", "half-open"] and 
            cb["failure_count"] >= cb["failure_threshold"]):
            cb["state"] = "open"
            logger.warning(f"Circuit breaker for '{api_name}' opened")
            
    async def health_check_all(self) -> Dict[str, bool]:
        """Проверка здоровья всех зарегистрированных API"""
        results = {}
        healthy_count = 0
        
        for name, client in self.clients.items():
            try:
                is_healthy = await client.health_check()
                results[name] = is_healthy
                if is_healthy:
                    healthy_count += 1
            except Exception as e:
                logger.error(f"Health check failed for '{name}': {e}")
                results[name] = False
                
        self.global_stats["healthy_apis"] = healthy_count
        return results
        
    async def get_global_stats(self) -> Dict[str, Any]:
        """Получение глобальной статистики"""
        api_stats = {}
        
        for name, client in self.clients.items():
            api_stats[name] = {
                **client.get_stats(),
                "circuit_breaker": dict(self.circuit_breakers[name])
            }
            
        return {
            "global": dict(self.global_stats),
            "apis": api_stats
        }
        
    async def shutdown(self):
        """Закрытие всех соединений"""
        for client in self.clients.values():
            await client.disconnect()
        self.clients.clear()
        self.circuit_breakers.clear()

# Фабричные функции

def create_rest_endpoint(name: str, base_url: str, 
                        rate_limit: Optional[int] = None) -> APIEndpoint:
    """Создание REST API endpoint"""
    return APIEndpoint(
        name=name,
        base_url=base_url,
        protocol=APIProtocol.REST,
        rate_limit=rate_limit
    )

def create_api_key_auth(api_key: str, header: str = "X-API-Key") -> AuthConfig:
    """Создание конфигурации API key аутентификации"""
    return AuthConfig(
        method=AuthMethod.API_KEY,
        credentials={
            "api_key": api_key,
            "header": header
        }
    )

def create_bearer_token_auth(token: str) -> AuthConfig:
    """Создание конфигурации Bearer token аутентификации"""
    return AuthConfig(
        method=AuthMethod.BEARER_TOKEN,
        credentials={"token": token}
    )