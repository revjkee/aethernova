# -*- coding: utf-8 -*-
"""
Bitcoin Core adapter for ledger-core
Асинхронный JSON-RPC клиент с устойчивостью к сбоям:
- Поддержка mainnet/testnet/regtest
- Получение транзакций/блоков, статуса mempool
- Оценка комиссии (estimatesmartfee) с fallback'ами
- Валидация адресов (validateaddress / getaddressinfo)
- Остаток по адресу через scantxoutset (при наличии) или баланс кошелька (если wallet_mode)
- Отправка сырой транзакции (sendrawtransaction)
- Декодирование raw tx (decoderawtransaction)
- Health-check (getblockchaininfo)
- Кэш короткоживущий для частых запросов
- Ретраи с экспоненциальной задержкой + простой circuit breaker
- Метрики/аудит хуки

Зависимости:
    pip install httpx pydantic
Совместимо с Python 3.10+
"""

from __future__ import annotations

import asyncio
import base64
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple, Protocol

import httpx
from pydantic import BaseModel, Field, validator


# ============================ Конфигурация и типы ============================

class Network(str, Enum):
    mainnet = "mainnet"
    testnet = "testnet"
    regtest = "regtest"

class FeeMode(str, Enum):
    conservative = "CONSERVATIVE"
    economical = "ECONOMICAL"

class HealthStatus(str, Enum):
    ok = "ok"
    degraded = "degraded"
    down = "down"

@dataclass
class BitcoinConfig:
    rpc_url: str               # http(s)://host:port
    rpc_user: str
    rpc_password: str
    network: Network = Network.mainnet
    timeout_s: float = 4.0
    max_retries: int = 4
    backoff_base_ms: int = 100
    backoff_cap_ms: int = 2000
    cb_failure_threshold: int = 5
    cb_reset_timeout_s: int = 30
    cache_ttl_s: int = 3       # короткий TTL кэша горячих запросов
    wallet_mode: bool = False  # true — разрешаем wallet RPC (getbalance, listunspent, sign..)
    wallet_name: Optional[str] = None  # если указан конкретный кошелек

class MetricsHook(Protocol):
    def __call__(self, name: str, value: float, tags: Optional[Dict[str, str]] = None) -> None: ...

class AuditHook(Protocol):
    def __call__(self, event: str, payload: Dict[str, Any]) -> None: ...


# ============================ Исключения ============================

class BitcoinError(Exception): ...
class RpcError(BitcoinError): ...
class CircuitOpen(BitcoinError): ...
class NotSupported(BitcoinError): ...


# ============================ Внутренние помощники ============================

def _basic_auth(user: str, password: str) -> str:
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return f"Basic {token}"

def _jittered_backoff(attempt: int, base_ms: int, cap_ms: int) -> float:
    exp = min(cap_ms, base_ms * (2 ** attempt))
    # 0.5..1.5 * exp
    import random as _random
    return (exp / 1000.0) * (0.5 + _random.random())

class _CircuitBreaker:
    def __init__(self, threshold: int, reset_timeout_s: int):
        self._threshold = max(1, threshold)
        self._reset = max(1, reset_timeout_s)
        self._fails = 0
        self._opened_at: Optional[float] = None

    def can_pass(self) -> bool:
        if self._opened_at is None:
            return True
        return (time.time() - self._opened_at) >= self._reset

    def record_success(self) -> None:
        self._fails = 0
        self._opened_at = None

    def record_failure(self) -> None:
        self._fails += 1
        if self._fails >= self._threshold and self._opened_at is None:
            self._opened_at = time.time()


# ============================ RPC клиент ============================

class _RpcClient:
    def __init__(self, cfg: BitcoinConfig, metrics: Optional[MetricsHook] = None):
        self._cfg = cfg
        self._auth = _basic_auth(cfg.rpc_user, cfg.rpc_password)
        self._cb = _CircuitBreaker(cfg.cb_failure_threshold, cfg.cb_reset_timeout_s)
        self._metrics = metrics or (lambda n, v, t=None: None)
        self._cache: Dict[str, Tuple[float, Any]] = {}
        self._id = 0

    async def call(self, method: str, params: list[Any] | tuple[Any, ...] = ()) -> Any:
        # Ретраи + circuit breaker
        attempt = 0
        while True:
            if not self._cb.can_pass():
                raise CircuitOpen("circuit breaker open")
            try:
                self._id += 1
                payload = {"jsonrpc": "2.0", "id": self._id, "method": method, "params": list(params)}
                headers = {"authorization": self._auth, "content-type": "application/json"}
                timeout = httpx.Timeout(self._cfg.timeout_s)
                async with httpx.AsyncClient(timeout=timeout) as client:
                    r = await client.post(self._cfg.rpc_url, json=payload, headers=headers)
                if r.status_code >= 500:
                    raise RpcError(f"HTTP {r.status_code}")
                data = r.json()
                if "error" in data and data["error"] is not None:
                    raise RpcError(str(data["error"]))
                self._cb.record_success()
                return data.get("result")
            except (httpx.TimeoutException, httpx.NetworkError, RpcError) as e:
                self._cb.record_failure()
                if attempt >= self._cfg.max_retries:
                    raise RpcError(f"rpc failed after retries: {e}") from e
                attempt += 1
                self._metrics("bitcoin.rpc.retry", 1.0, {"method": method, "attempt": str(attempt)})
                await asyncio.sleep(_jittered_backoff(attempt, self._cfg.backoff_base_ms, self._cfg.backoff_cap_ms))

    def cache_get(self, key: str) -> Optional[Any]:
        item = self._cache.get(key)
        if not item:
            return None
        ts, val = item
        if (time.time() - ts) <= self._cfg.cache_ttl_s:
            return val
        self._cache.pop(key, None)
        return None

    def cache_set(self, key: str, value: Any) -> None:
        self._cache[key] = (time.time(), value)


# ============================ DTO выходных данных ============================

class ChainTip(BaseModel):
    network: Network
    blocks: int
    headers: int
    best_hash: str = Field(alias="bestblockhash")
    difficulty: float
    ibd: bool = Field(alias="initialblockdownload")

class TxSummaryVin(BaseModel):
    txid: Optional[str] = None
    vout: Optional[int] = None
    sequence: Optional[int] = None
    coinbase: Optional[str] = None

class TxSummaryVoutScript(BaseModel):
    addresses: Optional[List[str]] = None
    type: Optional[str] = None
    asm: Optional[str] = None
    hex: Optional[str] = None

class TxSummaryVout(BaseModel):
    value: float
    n: int
    scriptPubKey: TxSummaryVoutScript

class TxSummary(BaseModel):
    txid: str
    hash: str
    size: int
    vsize: int
    version: int
    locktime: int
    vin: List[TxSummaryVin]
    vout: List[TxSummaryVout]
    blockhash: Optional[str] = None
    confirmations: Optional[int] = None
    time: Optional[int] = None
    blocktime: Optional[int] = None

class FeeEstimate(BaseModel):
    feerate_sat_vb: int
    blocks_target: int
    mode: FeeMode

class AddressValidation(BaseModel):
    isvalid: bool
    address: Optional[str] = None
    scriptPubKey: Optional[str] = None
    ismine: Optional[bool] = None
    iswatchonly: Optional[bool] = None
    isscript: Optional[bool] = None
    iswitness: Optional[bool] = None
    witness_version: Optional[int] = Field(default=None, alias="witness_version")
    witness_program: Optional[str] = Field(default=None, alias="witness_program")

class UtxoBalance(BaseModel):
    # Сумма по адресам или по кошельку (если wallet_mode)
    confirmed_btc: float
    unconfirmed_btc: float


# ============================ Публичный протокол адаптера ============================

class BitcoinAdapter(Protocol):
    async def health(self) -> Tuple[HealthStatus, Dict[str, Any]]: ...
    async def get_chain_tip(self) -> ChainTip: ...
    async def get_tx(self, txid: str, verbose: bool = True) -> TxSummary: ...
    async def decode_raw_tx(self, hex_raw_tx: str) -> TxSummary: ...
    async def broadcast(self, hex_raw_tx: str, maxfeerate_btc_kvb: Optional[float] = None) -> str: ...
    async def estimate_fee(self, blocks: int = 6, mode: FeeMode = FeeMode.conservative) -> FeeEstimate: ...
    async def validate_address(self, address: str) -> AddressValidation: ...
    async def utxo_balance(self, addresses: Optional[List[str]] = None, minconf: int = 1) -> UtxoBalance: ...


# ============================ Реализация адаптера ============================

class BitcoinCoreAdapter(BitcoinAdapter):
    def __init__(
        self,
        cfg: BitcoinConfig,
        metrics: Optional[MetricsHook] = None,
        audit: Optional[AuditHook] = None,
    ):
        self._cfg = cfg
        self._rpc = _RpcClient(cfg, metrics=metrics)
        self._metrics = metrics or (lambda n, v, t=None: None)
        self._audit = audit or (lambda e, p: None)

    # ---------- Health ----------
    async def health(self) -> Tuple[HealthStatus, Dict[str, Any]]:
        try:
            c = self._rpc.cache_get("chaininfo")
            if not c:
                c = await self._rpc.call("getblockchaininfo")
                self._rpc.cache_set("chaininfo", c)
            status = HealthStatus.ok
            if c.get("initialblockdownload", False):
                status = HealthStatus.degraded
            return status, {
                "network": self._cfg.network.value,
                "blocks": c.get("blocks"),
                "headers": c.get("headers"),
                "ibd": c.get("initialblockdownload"),
                "verificationprogress": c.get("verificationprogress"),
            }
        except Exception as e:
            return HealthStatus.down, {"error": str(e)}

    # ---------- Chain tip ----------
    async def get_chain_tip(self) -> ChainTip:
        c = self._rpc.cache_get("chaininfo")
        if not c:
            c = await self._rpc.call("getblockchaininfo")
            self._rpc.cache_set("chaininfo", c)
        # Pydantic маппит алиасы автоматически
        return ChainTip(network=self._cfg.network, **c)

    # ---------- Transactions ----------
    async def get_tx(self, txid: str, verbose: bool = True) -> TxSummary:
        # getrawtransaction <txid> true
        res = await self._rpc.call("getrawtransaction", [txid, True])
        return TxSummary(**res)

    async def decode_raw_tx(self, hex_raw_tx: str) -> TxSummary:
        res = await self._rpc.call("decoderawtransaction", [hex_raw_tx])
        return TxSummary(**res)

    async def broadcast(self, hex_raw_tx: str, maxfeerate_btc_kvb: Optional[float] = None) -> str:
        params: List[Any] = [hex_raw_tx]
        # sendrawtransaction 2nd arg: maxfeerate (BTC/kvB) в современных версиях
        if maxfeerate_btc_kvb is not None:
            params.append(maxfeerate_btc_kvb)
        txid = await self._rpc.call("sendrawtransaction", params)
        self._audit("bitcoin.tx.broadcast", {"txid": txid, "len": len(hex_raw_tx) // 2})
        self._metrics("bitcoin.broadcast", 1.0, {"network": self._cfg.network.value})
        return txid

    # ---------- Fees ----------
    async def estimate_fee(self, blocks: int = 6, mode: FeeMode = FeeMode.conservative) -> FeeEstimate:
        # estimatesmartfee <conf_target> <estimate_mode>
        res = await self._rpc.call("estimatesmartfee", [int(blocks), mode.value])
        feerate_btc_kvb = res.get("feerate")
        if feerate_btc_kvb is None:
            # fallback: попробуем иной режим/цель
            alt = await self._rpc.call("estimatesmartfee", [6, FeeMode.economical.value])
            feerate_btc_kvb = alt.get("feerate", 0.00001000)  # минимально разумный дефолт
        # Переведём в сат/вбайт: 1 BTC = 1e8 сат; feerate: BTC/kvB => сат/вбайт = feerate * 1e8 / 1000
        sat_vb = max(1, int(round((feerate_btc_kvb * 1e8) / 1000.0)))
        return FeeEstimate(feerate_sat_vb=sat_vb, blocks_target=int(blocks), mode=mode)

    # ---------- Address validation ----------
    async def validate_address(self, address: str) -> AddressValidation:
        # Для testnet/regtest адресные префиксы отличаются — Bitcoin Core сам знает сеть
        res = await self._rpc.call("validateaddress", [address])
        # enrich сведениями из getaddressinfo (если доступно в wallet_mode)
        if self._cfg.wallet_mode:
            try:
                info = await self._wallet_call("getaddressinfo", [address])
                res.update({k: v for k, v in info.items() if k in ("ismine", "iswatchonly", "isscript", "iswitness", "witness_version", "witness_program")})
            except Exception:
                pass
        return AddressValidation(**res)

    # ---------- UTXO balance ----------
    async def utxo_balance(self, addresses: Optional[List[str]] = None, minconf: int = 1) -> UtxoBalance:
        if self._cfg.wallet_mode and (addresses is None or len(addresses) == 0):
            # Используем баланс кошелька
            # getbalances -> {mine: {trusted, untrusted_pending, immature}, watchonly: {...}}
            b = await self._wallet_call("getbalances")
            mine = b.get("mine", {})
            confirmed = float(mine.get("trusted", 0.0))
            unconfirmed = float(mine.get("untrusted_pending", 0.0))
            return UtxoBalance(confirmed_btc=confirmed, unconfirmed_btc=unconfirmed)

        if not addresses:
            raise NotSupported("address list required when wallet_mode is False")

        # Быстрый путь: scantxoutset "start" [{"desc":"addr(…)"}, ...] доступен только с включенной опцией.
        # Если выключено — можно fallback на listunspent при wallet_mode и addmultisigaddress/importaddress заранее.
        try:
            scan_items = [{"desc": f"addr({addr})"} for addr in addresses]
            res = await self._rpc.call("scantxoutset", ["start", scan_items])
            utxos = res.get("unspents", [])
            confirmed_btc = sum(float(u.get("amount", 0.0)) for u in utxos if u.get("height", 0) > 0)
            unconfirmed_btc = sum(float(u.get("amount", 0.0)) for u in utxos if u.get("height", 0) == 0)
            return UtxoBalance(confirmed_btc=confirmed_btc, unconfirmed_btc=unconfirmed_btc)
        except RpcError:
            if self._cfg.wallet_mode:
                # fallback: listunspent с фильтрацией по адресам
                utxos = await self._wallet_call("listunspent", [minconf, 9999999, addresses])
                confirmed_btc = sum(float(u.get("amount", 0.0)) for u in utxos)
                # listunspent не включает неподтверждённые; запросим mempool через getaddressinfo? Опустим — 0.
                return UtxoBalance(confirmed_btc=confirmed_btc, unconfirmed_btc=0.0)
            raise

    # ==================== Вспомогательные wallet вызовы ====================

    async def _wallet_call(self, method: str, params: list[Any] | tuple[Any, ...] = ()) -> Any:
        if not self._cfg.wallet_mode:
            raise NotSupported("wallet RPC disabled")
        # Bitcoin Core wallet RPC via /wallet/<name>
        if not self._cfg.wallet_name:
            # Для дефолтного кошелька адрес — /wallet/<empty>? Обычно требуется явное имя.
            # Попытаемся вызвать общий метод без смены URL.
            return await self._rpc.call(method, params)
        # Для конкретного кошелька открываем отдельный endpoint.
        # Реализуем отдельным клиентским вызовом, сохраним ретраи/авторизацию.
        attempt = 0
        auth = _basic_auth(self._cfg.rpc_user, self._cfg.rpc_password)
        while True:
            try:
                headers = {"authorization": auth, "content-type": "application/json"}
                payload = {"jsonrpc": "2.0", "id": int(time.time()*1000) % 1_000_000, "method": method, "params": list(params)}
                timeout = httpx.Timeout(self._cfg.timeout_s)
                wallet_url = f"{self._cfg.rpc_url}/wallet/{self._cfg.wallet_name}"
                async with httpx.AsyncClient(timeout=timeout) as client:
                    r = await client.post(wallet_url, json=payload, headers=headers)
                if r.status_code >= 500:
                    raise RpcError(f"HTTP {r.status_code}")
                data = r.json()
                if "error" in data and data["error"] is not None:
                    raise RpcError(str(data["error"]))
                return data.get("result")
            except (httpx.TimeoutException, httpx.NetworkError, RpcError) as e:
                if attempt >= self._cfg.max_retries:
                    raise RpcError(f"wallet rpc failed: {e}") from e
                attempt += 1
                await asyncio.sleep(_jittered_backoff(attempt, self._cfg.backoff_base_ms, self._cfg.backoff_cap_ms))


# ============================ Фабрика ============================

def make_bitcoin_adapter(cfg: BitcoinConfig, metrics: Optional[MetricsHook] = None, audit: Optional[AuditHook] = None) -> BitcoinAdapter:
    return BitcoinCoreAdapter(cfg=cfg, metrics=metrics, audit=audit)


# ============================ Пример использования (опционально, для локального теста) ============================

if __name__ == "__main__":
    # Демонстрационный запуск на regtest (требуется запущенный bitcoind)
    async def main():
        cfg = BitcoinConfig(
            rpc_url="http://127.0.0.1:18443",
            rpc_user="user",
            rpc_password="pass",
            network=Network.regtest,
            wallet_mode=True,
            wallet_name="default",
        )
        adapter = make_bitcoin_adapter(cfg)

        print("Health:", await adapter.health())
        tip = await adapter.get_chain_tip()
        print("Tip:", tip.dict())

        fee = await adapter.estimate_fee(blocks=2)
        print("Fee:", fee.dict())

        addr = "bcrt1qq..."  # замените на реальный адрес из вашего кошелька regtest
        try:
            v = await adapter.validate_address(addr)
            print("Validate:", v.dict())
        except RpcError as e:
            print("Validate error:", e)

    asyncio.run(main())
