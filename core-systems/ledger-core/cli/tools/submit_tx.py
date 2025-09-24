#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ledger-core/ledger/cli/tools/submit_tx.py

Промышленный CLI для отправки EVM-транзакций по JSON-RPC:
- send-raw: отправка подписанной транзакции (hex) через eth_sendRawTransaction
- send:    (опционально) сборка+подпись EIP-1559 при наличии eth_account
- status:  ожидание/проверка чека по tx hash
- estimate: оценка maxFeePerGas/maxPriorityFeePerGas и nonce

Особенности:
- Асинхронный httpx client, экспоненциальные ретраи (сетевые/транзиентные)
- Тайм-ауты, структурированное логирование, коды возврата процесса
- Безопасный ввод сырой транзакции из stdin/файла (без логирования содержимого)
- Конфигурация: аргументы CLI, переменные окружения, .env (опционально)
- Акуратная обработка JSON-RPC ошибок (коды, сообщения, data)
- Ожидание receipt с настраиваемыми интервалом/тайм-аутом
- Идемпотентность на уровне сети за счет повторов по одному tx

ENV:
  LEDGER_RPC_URL, LEDGER_RPC_AUTH_BEARER, LEDGER_RPC_HEADERS_JSON

Зависимости:
  - httpx>=0.24
  - (опционально) eth-account>=0.9 для подписи в subcmd send

Примеры:
  echo 0x02f8... | submit_tx.py send-raw --rpc https://rpc... --wait
  submit_tx.py status 0xabc... --rpc https://rpc... --wait --timeout 120
  submit_tx.py estimate --rpc https://rpc... --from 0xdead... --to 0x.... --value 0 --chain-id 1
  submit_tx.py send --rpc https://... --from 0x... --to 0x... --value 1000000000000000 --privkey-file ./key.hex --chain-id 1 --wait
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple, Union

import httpx

# ---------- Логирование ----------

LOG = logging.getLogger("submit_tx")
_HANDLER = logging.StreamHandler(sys.stderr)
_FMT = logging.Formatter(
    fmt="%(asctime)s %(levelname)s %(name)s - %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S%z",
)
_HANDLER.setFormatter(_FMT)
LOG.addHandler(_HANDLER)
LOG.setLevel(logging.INFO)


# ---------- Утилиты HEX/JSON ----------

def _is_hex_str(s: str) -> bool:
    return s.startswith("0x") and all(c in "0123456789abcdefABCDEF" for c in s[2:])

def _to_hex(i: int) -> str:
    return hex(i)

def _to_hex_bytes(b: bytes) -> str:
    return "0x" + b.hex()

def _ensure_0x(s: str) -> str:
    return s if s.startswith("0x") else "0x" + s

def _read_all_stdin() -> str:
    data = sys.stdin.read()
    return data.strip()

def _read_file(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read().strip()

def _load_privkey_hex(path: Optional[str], inline: Optional[str]) -> Optional[str]:
    src = inline or ( _read_file(path) if path else None )
    if not src:
        return None
    src = src.strip()
    src = src[2:] if src.startswith("0x") else src
    if not all(c in "0123456789abcdefABCDEF" for c in src):
        raise ValueError("private key must be hex")
    if len(src) not in (64,):  # 32 bytes
        raise ValueError("private key must be 32 bytes hex (64 chars)")
    return "0x" + src.lower()


# ---------- Конфигурация ----------

@dataclass
class RpcConfig:
    url: str
    bearer: Optional[str] = None
    extra_headers: Optional[Dict[str, str]] = None
    timeout: float = 20.0

def _rpc_from_env_or_args(args: argparse.Namespace) -> RpcConfig:
    url = args.rpc or os.getenv("LEDGER_RPC_URL")
    if not url:
        raise SystemExit("RPC URL is required (use --rpc or LEDGER_RPC_URL)")

    bearer = args.rpc_bearer or os.getenv("LEDGER_RPC_AUTH_BEARER")
    hdr_json = args.rpc_headers or os.getenv("LEDGER_RPC_HEADERS_JSON")
    extra = None
    if hdr_json:
        try:
            extra = json.loads(hdr_json)
            if not isinstance(extra, dict):
                raise ValueError
        except Exception:
            raise SystemExit("LEDGER_RPC_HEADERS_JSON must be a JSON object")

    return RpcConfig(url=url, bearer=bearer, extra_headers=extra, timeout=float(args.timeout))


# ---------- JSON-RPC Клиент ----------

class JsonRpcError(RuntimeError):
    def __init__(self, code: int, message: str, data: Any = None):
        super().__init__(f"JSON-RPC error {code}: {message} data={data!r}")
        self.code = code
        self.message = message
        self.data = data

class RpcClient:
    def __init__(self, cfg: RpcConfig, retries: int = 3, backoff: float = 0.5):
        self.cfg = cfg
        self.retries = retries
        self.backoff = backoff
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self):
        headers = {"Content-Type": "application/json"}
        if self.cfg.bearer:
            headers["Authorization"] = f"Bearer {self.cfg.bearer}"
        if self.cfg.extra_headers:
            headers.update(self.cfg.extra_headers)
        self._client = httpx.AsyncClient(
            base_url=self.cfg.url,
            headers=headers,
            timeout=self.cfg.timeout,
        )
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self._client:
            await self._client.aclose()

    async def call(self, method: str, params: list) -> Any:
        assert self._client is not None
        payload = {"jsonrpc": "2.0", "id": int(time.time()*1000) & 0x7FFFFFFF, "method": method, "params": params}
        last_exc: Optional[Exception] = None
        for attempt in range(1, self.retries + 1):
            try:
                r = await self._client.post("", json=payload)
                r.raise_for_status()
                data = r.json()
                if "error" in data:
                    err = data["error"]
                    raise JsonRpcError(err.get("code", -32000), err.get("message", "Unknown error"), err.get("data"))
                return data.get("result")
            except (httpx.ReadTimeout, httpx.ConnectTimeout, httpx.RemoteProtocolError, httpx.RequestError) as e:
                last_exc = e
                if attempt == self.retries:
                    raise
                wait = min(self.backoff * (2 ** (attempt - 1)), 3.0)
                LOG.warning("RPC transient error on %s attempt %d/%d, retrying in %.2fs: %s", method, attempt, self.retries, wait, e)
                await asyncio.sleep(wait)
            except JsonRpcError:
                # Не ретраим логические ошибки узла
                raise
        if last_exc:
            raise last_exc
        raise RuntimeError("unreachable")


# ---------- Высокоуровневые операции ----------

async def rpc_chain_id(rpc: RpcClient) -> int:
    res = await rpc.call("eth_chainId", [])
    return int(res, 16) if isinstance(res, str) else int(res)

async def rpc_get_nonce(rpc: RpcClient, address: str, tag: str = "pending") -> int:
    res = await rpc.call("eth_getTransactionCount", [address, tag])
    return int(res, 16)

async def rpc_send_raw(rpc: RpcClient, raw_hex: str) -> str:
    if not _is_hex_str(raw_hex):
        raise ValueError("raw transaction must be hex string with 0x prefix")
    tx_hash = await rpc.call("eth_sendRawTransaction", [raw_hex])
    return str(tx_hash)

async def rpc_get_receipt(rpc: RpcClient, tx_hash: str) -> Optional[Dict[str, Any]]:
    res = await rpc.call("eth_getTransactionReceipt", [tx_hash])
    return res  # None пока нет чека

async def rpc_get_tip(rpc: RpcClient) -> int:
    # baseFee via latest block
    block = await rpc.call("eth_getBlockByNumber", ["latest", False])
    base_fee_hex = block.get("baseFeePerGas")
    return int(base_fee_hex, 16) if base_fee_hex else 0

async def rpc_estimate_gas(rpc: RpcClient, tx: Dict[str, Any]) -> int:
    res = await rpc.call("eth_estimateGas", [tx])
    return int(res, 16)

async def rpc_get_gas_price(rpc: RpcClient) -> int:
    res = await rpc.call("eth_gasPrice", [])
    return int(res, 16)


async def wait_for_receipt(
    rpc: RpcClient,
    tx_hash: str,
    poll_interval: float = 2.0,
    timeout: float = 120.0,
) -> Tuple[Optional[Dict[str, Any]], bool]:
    """
    Возвращает (receipt, timed_out)
    """
    start = time.time()
    while True:
        rec = await rpc_get_receipt(rpc, tx_hash)
        if rec is not None:
            return rec, False
        if (time.time() - start) >= timeout:
            return None, True
        await asyncio.sleep(poll_interval)


# ---------- EIP-1559 сборка/подпись (опционально) ----------

def _eth_account_available() -> bool:
    try:
        import eth_account  # noqa
        return True
    except Exception:
        return False

async def build_eip1559_tx(
    rpc: RpcClient,
    from_addr: str,
    to_addr: str,
    value_wei: int,
    chain_id: Optional[int],
    gas_limit: Optional[int],
    max_fee_per_gas: Optional[int],
    max_priority_fee_per_gas: Optional[int],
    nonce: Optional[int],
    data_hex: Optional[str],
) -> Dict[str, Any]:
    # Адреса и поля приводим к 0x hex
    tx: Dict[str, Any] = {
        "from": from_addr,
        "to": to_addr,
        "value": _to_hex(value_wei),
    }
    if data_hex:
        tx["data"] = data_hex if data_hex.startswith("0x") else ("0x" + data_hex)

    # chain_id
    if chain_id is None:
        try:
            cid = await rpc_chain_id(rpc)
            chain_id = cid
            LOG.debug("Resolved chain_id: %d", chain_id)
        except Exception:
            LOG.warning("Failed to resolve chain_id from RPC, continuing without it.")
    # газ/цены
    if max_fee_per_gas is None or max_priority_fee_per_gas is None:
        # попробуем оценить
        base_fee = await rpc_get_tip(rpc)
        gp = await rpc_get_gas_price(rpc)  # fallback эвристика
        if max_priority_fee_per_gas is None:
            # Приорити: берем минимум из 1.5 gwei и gasPrice/baseFee эвристик
            default_tip = max(1_500_000_000, gp // 2)
            max_priority_fee_per_gas = default_tip
        if max_fee_per_gas is None:
            # Общий максимум: baseFee*2 + priority
            max_fee_per_gas = max(base_fee * 2 + max_priority_fee_per_gas, gp)
        LOG.info("Fees resolved: max_fee_per_gas=%d, max_priority=%d", max_fee_per_gas, max_priority_fee_per_gas)

    # nonce
    if nonce is None:
        nonce = await rpc_get_nonce(rpc, from_addr, "pending")

    # gas limit
    if gas_limit is None:
        # минимальная оценка + запас
        estimate = await rpc_estimate_gas(rpc, {**tx, "from": from_addr})
        gas_limit = int(estimate * 1.15)

    # формируем "сырую" структуру
    built = {
        "chainId": chain_id,
        "from": from_addr,
        "to": to_addr,
        "nonce": nonce,
        "value": value_wei,
        "gas": gas_limit,
        "maxFeePerGas": max_fee_per_gas,
        "maxPriorityFeePerGas": max_priority_fee_per_gas,
        "data": tx.get("data", "0x"),
        "type": 2,  # EIP-1559
    }
    return built

def sign_eip1559_tx_eth_account(tx: Dict[str, Any], privkey_hex: str) -> str:
    """
    Подпись через eth_account (если установлен). Возвращает rawTx hex.
    """
    try:
        from eth_account import Account
        from eth_account._utils.legacy_transactions import serializable_unsigned_transaction_from_dict
        # eth-account самостоятельно корректно обработает EIP-1559 поля
        signed = Account.sign_transaction(tx, privkey_hex)
        return signed.rawTransaction.hex()
    except Exception as e:
        raise SystemExit(f"Signing failed: {e}")


# ---------- CLI команды ----------

async def cmd_send_raw(args: argparse.Namespace) -> int:
    rpc_cfg = _rpc_from_env_or_args(args)
    raw_tx_hex: Optional[str] = None

    if args.raw:
        raw_tx_hex = args.raw.strip()
    elif args.file:
        raw_tx_hex = _read_file(args.file)
    else:
        if sys.stdin.isatty():
            raise SystemExit("Provide --raw/--file or pipe raw tx hex via stdin")
        raw_tx_hex = _read_all_stdin()

    if not raw_tx_hex:
        raise SystemExit("Empty raw transaction")
    raw_tx_hex = raw_tx_hex.strip()
    if not raw_tx_hex.startswith("0x"):
        raw_tx_hex = "0x" + raw_tx_hex

    async with RpcClient(rpc_cfg, retries=int(args.retries), backoff=float(args.backoff)) as rpc:
        try:
            tx_hash = await rpc_send_raw(rpc, raw_tx_hex)
        except JsonRpcError as jre:
            LOG.error("Node rejected transaction: code=%d message=%s data=%r", jre.code, jre.message, jre.data)
            return 2
        except Exception as e:
            LOG.error("Failed to submit transaction: %s", e)
            return 2

        print(tx_hash)
        if args.wait:
            rec, to = await wait_for_receipt(
                rpc,
                tx_hash,
                poll_interval=float(args.poll_interval),
                timeout=float(args.timeout),
            )
            if to:
                LOG.error("Timed out waiting for receipt")
                return 3
            status_hex = rec.get("status")
            status = int(status_hex, 16) if status_hex else 0
            LOG.info("Receipt status=%d block=%s gasUsed=%s", status, rec.get("blockNumber"), rec.get("gasUsed"))
            return 0 if status == 1 else 4
        return 0


async def cmd_status(args: argparse.Namespace) -> int:
    rpc_cfg = _rpc_from_env_or_args(args)
    tx_hash = args.tx_hash.strip()
    if not tx_hash.startswith("0x"):
        raise SystemExit("tx_hash must be 0x-prefixed hex")
    async with RpcClient(rpc_cfg, retries=int(args.retries), backoff=float(args.backoff)) as rpc:
        if args.wait:
            rec, to = await wait_for_receipt(
                rpc,
                tx_hash,
                poll_interval=float(args.poll_interval),
                timeout=float(args.timeout),
            )
            if to:
                LOG.error("Timed out waiting for receipt")
                return 3
            status_hex = rec.get("status")
            status = int(status_hex, 16) if status_hex else 0
            print(json.dumps(rec, indent=2))
            return 0 if status == 1 else 4
        # one-shot check
        rec = await rpc_get_receipt(rpc, tx_hash)
        if rec is None:
            LOG.info("Receipt not found yet")
            return 1
        print(json.dumps(rec, indent=2))
        status_hex = rec.get("status")
        status = int(status_hex, 16) if status_hex else 0
        return 0 if status == 1 else 4


async def cmd_estimate(args: argparse.Namespace) -> int:
    rpc_cfg = _rpc_from_env_or_args(args)
    from_addr = args.from_addr
    to_addr = args.to_addr
    value_wei = int(args.value)
    data_hex = args.data
    async with RpcClient(rpc_cfg, retries=int(args.retries), backoff=float(args.backoff)) as rpc:
        try:
            tx = await build_eip1559_tx(
                rpc,
                from_addr=from_addr,
                to_addr=to_addr,
                value_wei=value_wei,
                chain_id=int(args.chain_id) if args.chain_id else None,
                gas_limit=int(args.gas) if args.gas else None,
                max_fee_per_gas=int(args.max_fee_per_gas) if args.max_fee_per_gas else None,
                max_priority_fee_per_gas=int(args.max_priority_fee_per_gas) if args.max_priority_fee_per_gas else None,
                nonce=int(args.nonce) if args.nonce else None,
                data_hex=data_hex,
            )
            # Выводим оцененные параметры в JSON
            out = {
                "chainId": tx["chainId"],
                "nonce": tx["nonce"],
                "gas": tx["gas"],
                "maxFeePerGas": tx["maxFeePerGas"],
                "maxPriorityFeePerGas": tx["maxPriorityFeePerGas"],
            }
            print(json.dumps(out, indent=2))
            return 0
        except JsonRpcError as jre:
            LOG.error("Estimate failed: code=%d message=%s data=%r", jre.code, jre.message, jre.data)
            return 2
        except Exception as e:
            LOG.error("Estimate failed: %s", e)
            return 2


async def cmd_send(args: argparse.Namespace) -> int:
    if not _eth_account_available():
        LOG.error("eth-account is not installed; install eth-account to use 'send'")
        return 5
    rpc_cfg = _rpc_from_env_or_args(args)

    privkey = _load_privkey_hex(args.privkey_file, args.privkey)
    if not privkey:
        raise SystemExit("Provide --privkey or --privkey-file")

    from_addr = args.from_addr
    to_addr = args.to_addr
    value_wei = int(args.value)
    data_hex = args.data

    async with RpcClient(rpc_cfg, retries=int(args.retries), backoff=float(args.backoff)) as rpc:
        try:
            tx = await build_eip1559_tx(
                rpc,
                from_addr=from_addr,
                to_addr=to_addr,
                value_wei=value_wei,
                chain_id=int(args.chain_id) if args.chain_id else None,
                gas_limit=int(args.gas) if args.gas else None,
                max_fee_per_gas=int(args.max_fee_per_gas) if args.max_fee_per_gas else None,
                max_priority_fee_per_gas=int(args.max_priority_fee_per_gas) if args.max_priority_fee_per_gas else None,
                nonce=int(args.nonce) if args.nonce else None,
                data_hex=data_hex,
            )
            raw_hex = sign_eip1559_tx_eth_account(tx, privkey)
            LOG.info("Signed EIP-1559 tx; submitting...")
            tx_hash = await rpc_send_raw(rpc, raw_hex)
        except JsonRpcError as jre:
            LOG.error("Node rejected transaction: code=%d message=%s data=%r", jre.code, jre.message, jre.data)
            return 2
        except Exception as e:
            LOG.error("Failed to send: %s", e)
            return 2

        print(tx_hash)
        if args.wait:
            rec, to = await wait_for_receipt(
                rpc,
                tx_hash,
                poll_interval=float(args.poll_interval),
                timeout=float(args.timeout),
            )
            if to:
                LOG.error("Timed out waiting for receipt")
                return 3
            status_hex = rec.get("status")
            status = int(status_hex, 16) if status_hex else 0
            LOG.info("Receipt status=%d block=%s gasUsed=%s", status, rec.get("blockNumber"), rec.get("gasUsed"))
            return 0 if status == 1 else 4
        return 0


# ---------- Парсер аргументов ----------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="submit_tx",
        description="Industrial-grade JSON-RPC EVM transaction submitter",
    )
    p.add_argument("--rpc", help="RPC endpoint URL (or LEDGER_RPC_URL)")
    p.add_argument("--rpc-bearer", help="Bearer token (or LEDGER_RPC_AUTH_BEARER)")
    p.add_argument("--rpc-headers", help="Extra headers as JSON (or LEDGER_RPC_HEADERS_JSON)")
    p.add_argument("--timeout", type=float, default=20.0, help="HTTP timeout seconds (default: 20)")
    p.add_argument("--retries", type=int, default=3, help="Number of transient retries (default: 3)")
    p.add_argument("--backoff", type=float, default=0.5, help="Initial backoff seconds (default: 0.5)")
    p.add_argument("--verbose", action="store_true", help="Verbose logging")

    sub = p.add_subparsers(dest="cmd", required=True)

    # send-raw
    sraw = sub.add_parser("send-raw", help="Submit a signed raw transaction (hex)")
    sraw.add_argument("--raw", help="Raw tx hex (0x...)")
    sraw.add_argument("--file", help="File with raw tx hex")
    sraw.add_argument("--wait", action="store_true", help="Wait for receipt")
    sraw.add_argument("--timeout", type=float, default=120.0, help="Wait timeout seconds")
    sraw.add_argument("--poll-interval", type=float, default=2.0, help="Receipt poll interval seconds")
    sraw.set_defaults(func=cmd_send_raw)

    # status
    st = sub.add_parser("status", help="Fetch/wait for a receipt by tx hash")
    st.add_argument("tx_hash", help="Transaction hash (0x...)")
    st.add_argument("--wait", action="store_true", help="Wait for receipt")
    st.add_argument("--timeout", type=float, default=120.0, help="Wait timeout seconds")
    st.add_argument("--poll-interval", type=float, default=2.0, help="Receipt poll interval seconds")
    st.set_defaults(func=cmd_status)

    # estimate
    est = sub.add_parser("estimate", help="Estimate EIP-1559 fees, gas and nonce")
    est.add_argument("--from", dest="from_addr", required=True, help="Sender address (0x...)")
    est.add_argument("--to", dest="to_addr", required=True, help="Recipient address (0x...)")
    est.add_argument("--value", required=True, help="Value in wei (int)")
    est.add_argument("--data", default=None, help="Data payload hex (0x...)")
    est.add_argument("--chain-id", type=int, default=None)
    est.add_argument("--gas", type=int, default=None)
    est.add_argument("--max-fee-per-gas", dest="max_fee_per_gas", type=int, default=None)
    est.add_argument("--max-priority-fee-per-gas", dest="max_priority_fee_per_gas", type=int, default=None)
    est.add_argument("--nonce", type=int, default=None)
    est.set_defaults(func=cmd_estimate)

    # send (optional signing)
    snd = sub.add_parser("send", help="Build+sign EIP-1559 and submit (requires eth-account)")
    snd.add_argument("--from", dest="from_addr", required=True, help="Sender address (0x...)")
    snd.add_argument("--to", dest="to_addr", required=True, help="Recipient address (0x...)")
    snd.add_argument("--value", required=True, help="Value in wei (int)")
    snd.add_argument("--data", default=None, help="Data payload hex (0x...)")
    snd.add_argument("--chain-id", type=int, default=None)
    snd.add_argument("--gas", type=int, default=None)
    snd.add_argument("--max-fee-per-gas", dest="max_fee_per_gas", type=int, default=None)
    snd.add_argument("--max-priority-fee-per-gas", dest="max_priority_fee_per_gas", type=int, default=None)
    snd.add_argument("--nonce", type=int, default=None)
    snd.add_argument("--privkey", default=None, help="Private key hex (0x...)")
    snd.add_argument("--privkey-file", default=None, help="Private key file (hex)")
    snd.add_argument("--wait", action="store_true", help="Wait for receipt")
    snd.add_argument("--timeout", type=float, default=120.0, help="Wait timeout seconds")
    snd.add_argument("--poll-interval", type=float, default=2.0, help="Receipt poll interval seconds")
    snd.set_defaults(func=cmd_send)

    return p


# ---------- Main ----------

def main(argv: Optional[list[str]] = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.verbose:
        LOG.setLevel(logging.DEBUG)
        httpx_logger = logging.getLogger("httpx")
        httpx_logger.setLevel(logging.WARNING)

    try:
        return asyncio.run(args.func(args))
    except KeyboardInterrupt:
        LOG.error("Interrupted")
        return 130
    except SystemExit as se:
        # передаем как есть
        raise se
    except Exception as e:
        LOG.exception("Unhandled error: %s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
