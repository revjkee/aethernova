# -*- coding: utf-8 -*-
"""
physical-integration-core/cli/tools/send_command.py

CLI для отправки команд в edge-шлюз через AMQP (RabbitMQ).
Совместим с:
  - physical_integration/edge/gateway.py (очередь команд и события)
  - physical_integration/protocols/amqp_client.py (публикация с confirm/mandatory)

Функции:
- Отправка команд: ping | reload_config | emit | custom.
- Маршрутизация по exchange команд (binding '#'), настраиваемый routing-key.
- --wait/-w: ожидание ответа на ping (edge.events.pong) по полю ref через временную очередь.
- TLS (CA/cert/key), idempotency-key, correlation-id, expiration, headers.
- Источник payload: --data JSON | --data-file | stdin (-) для custom/emit.
- Коды возврата: 0 — успех, 2 — таймаут ожидания, 3 — ошибка публикации/сети, 4 — ошибка ввода.

Зависимости:
  aio-pika>=9.4
  (опционально) uvloop на Linux для ускорения

Пример:
  python -m cli.tools.send_command ping --amqp-url amqps://user:pass@mq:5671/ \
      --events-exchange edge.events.x --cmd-exchange edge.commands.q.x \
      --site plant-1 --node edge-01 --wait --timeout 5

  echo '{"data":{"k":"v"}}' | python -m cli.tools.send_command emit - --rk "sites.plant-1.edge-01.emit"
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
import ssl
import uuid
from dataclasses import dataclass
from typing import Any, Optional, Dict

import aio_pika
from aio_pika import ExchangeType, Message, DeliveryMode, RobustConnection


# ------------------------------- Utils ---------------------------------------

def _mk_ssl_context(cafile: Optional[str], certfile: Optional[str], keyfile: Optional[str], verify: bool) -> Optional[ssl.SSLContext]:
    if not (cafile or certfile or keyfile or not verify):
        return None
    ctx = ssl.create_default_context(cafile=cafile) if verify else ssl._create_unverified_context()
    if certfile and keyfile:
        ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _read_json_data(arg: Optional[str], file: Optional[str]) -> Dict[str, Any]:
    if arg and arg != "-":
        try:
            return json.loads(arg)
        except Exception as e:
            raise ValueError(f"Invalid JSON in --data: {e}") from e
    if file:
        with (sys.stdin if file == "-" else open(file, "r", encoding="utf-8")) as f:
            return json.load(f)
    return {}


def _now_ms() -> int:
    return int(time.time() * 1000)


# ------------------------------- CLI opts ------------------------------------

@dataclass
class Options:
    amqp_url: str
    cmd_exchange: str
    events_exchange: str
    routing_key: str
    cmd: str
    site: str
    node: str
    wait: bool
    timeout: float
    expiration_ms: Optional[int]
    idempotency_key: Optional[str]
    correlation_id: Optional[str]
    headers: Dict[str, Any]
    data_json: Dict[str, Any]
    ca: Optional[str]
    cert: Optional[str]
    key: Optional[str]
    ssl_verify: bool
    publisher_confirms: bool


def parse_args(argv: list[str]) -> Options:
    p = argparse.ArgumentParser(description="Send command to edge gateway via AMQP")
    p.add_argument("cmd", choices=["ping", "reload_config", "emit", "custom"], help="Command type")
    p.add_argument("data", nargs="?", default=None,
                   help="Inline JSON for 'emit'/'custom' or '-' to read JSON from stdin")
    p.add_argument("--data-file", default=None, help="Path to JSON file or '-' for stdin")
    p.add_argument("--amqp-url", default=os.getenv("AMQP_URL", "amqps://guest:guest@localhost:5671/"))
    p.add_argument("--cmd-exchange", default=os.getenv("EDGE_Q_COMMANDS", "edge.commands.q") + ".x",
                   help="Exchange to publish commands (queue is bound with '#')")
    p.add_argument("--events-exchange", default=os.getenv("EDGE_X_EVENTS", "edge.events.x"),
                   help="Exchange where gateway publishes events")
    p.add_argument("--rk", dest="routing_key", default=os.getenv("CMD_ROUTING_KEY", "edge.commands.any"),
                   help="Routing key for command message")
    p.add_argument("--site", default=os.getenv("SITE_ID", "default-site"))
    p.add_argument("--node", default=os.getenv("NODE_ID", "edge-01"))
    p.add_argument("--wait", "-w", action="store_true", help="Wait for pong (only for 'ping')")
    p.add_argument("--timeout", type=float, default=float(os.getenv("CMD_TIMEOUT", "5")), help="Wait timeout seconds")
    p.add_argument("--expiration-ms", type=int, default=None, help="Per-message TTL (ms)")
    p.add_argument("--idempotency-key", default=None, help="Idempotency key header")
    p.add_argument("--correlation-id", default=None, help="AMQP correlation_id")
    p.add_argument("--header", action="append", default=[], metavar="K=V", help="Extra header(s)")
    p.add_argument("--ca", default=os.getenv("AMQP_CA"), help="CA file (PEM)")
    p.add_argument("--cert", default=os.getenv("AMQP_CERT"), help="Client cert (PEM)")
    p.add_argument("--key", default=os.getenv("AMQP_KEY"), help="Client key (PEM)")
    p.add_argument("--no-verify", action="store_true", help="Disable TLS verification")
    p.add_argument("--no-confirms", action="store_true", help="Disable publisher confirms")

    args = p.parse_args(argv)

    headers: Dict[str, Any] = {}
    for item in args.header or []:
        if "=" not in item:
            raise SystemExit(f"Invalid --header '{item}', expected K=V")
        k, v = item.split("=", 1)
        headers[k.strip()] = v.strip()

    # Build data_json
    data_json = _read_json_data(args.data, args.data_file)

    return Options(
        amqp_url=args.amqp_url,
        cmd_exchange=args.cmd_exchange,
        events_exchange=args.events_exchange,
        routing_key=args.routing_key,
        cmd=args.cmd,
        site=args.site,
        node=args.node,
        wait=bool(args.wait),
        timeout=float(args.timeout),
        expiration_ms=args.expiration_ms,
        idempotency_key=args.idempotency_key,
        correlation_id=args.correlation_id,
        headers=headers,
        data_json=data_json,
        ca=args.ca,
        cert=args.cert,
        key=args.key,
        ssl_verify=not args.no_verify,
        publisher_confirms=not args.no_confirms,
    )


# ------------------------------- AMQP logic ----------------------------------

async def _connect(url: str, confirms: bool, ssl_ctx: Optional[ssl.SSLContext]) -> tuple[RobustConnection, aio_pika.RobustChannel]:
    conn = await aio_pika.connect_robust(url, ssl=ssl_ctx is not None, ssl_context=ssl_ctx, timeout=10, heartbeat=30)
    ch = await conn.channel(publisher_confirms=confirms)
    await ch.set_qos(prefetch_count=16)
    return conn, ch


async def _ensure_exchange(ch: aio_pika.RobustChannel, name: str, type_: ExchangeType = ExchangeType.TOPIC):
    try:
        ex = await ch.get_exchange(name, ensure=True)
    except Exception:
        ex = await ch.declare_exchange(name, type_, durable=True)
    return ex


async def send(opts: Options) -> int:
    ssl_ctx = _mk_ssl_context(opts.ca, opts.cert, opts.key, opts.ssl_verify)
    conn, ch = await _connect(opts.amqp_url, opts.publisher_confirms, ssl_ctx)
    try:
        ex_cmd = await _ensure_exchange(ch, opts.cmd_exchange, ExchangeType.TOPIC)

        # Compose payload
        ref = str(uuid.uuid4())
        payload: Dict[str, Any] = {"cmd": opts.cmd, "site": opts.site, "node": opts.node, "ts": time.time()}
        if opts.cmd == "ping":
            payload["ref"] = ref
        elif opts.cmd == "reload_config":
            pass
        elif opts.cmd == "emit":
            payload.update(opts.data_json or {})
        elif opts.cmd == "custom":
            # ожидаем произвольный JSON с полями cmd и т.д. при необходимости
            payload.update(opts.data_json or {})

        headers = dict(opts.headers)
        if opts.idempotency_key:
            headers.setdefault("x-idempotency-key", opts.idempotency_key)

        msg = Message(
            body=json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
            content_type="application/json",
            delivery_mode=DeliveryMode.PERSISTENT,
            correlation_id=opts.correlation_id or ref,
            expiration=(opts.expiration_ms / 1000.0) if opts.expiration_ms else None,
            timestamp=time.time(),
            app_id="pic-cli",
            headers=headers,
        )

        await ex_cmd.publish(msg, routing_key=opts.routing_key, mandatory=True)

        # If not waiting, we are done
        if not opts.wait or opts.cmd != "ping":
            print(json.dumps({"status": "ok", "ref": ref, "published_to": opts.cmd_exchange, "rk": opts.routing_key}, ensure_ascii=False))
            return 0

        # Wait for pong on events exchange (edge.events.pong with matching ref)
        ex_evt = await _ensure_exchange(ch, opts.events_exchange, ExchangeType.TOPIC)

        # Create exclusive, autodelete queue
        q = await ch.declare_queue(name="", exclusive=True, auto_delete=True, durable=False)
        await q.bind(ex_evt, routing_key="edge.events.pong")

        future: asyncio.Future[dict] = asyncio.get_event_loop().create_future()

        async def _consumer(message: aio_pika.IncomingMessage):
            async with message.process(requeue=False, ignore_processed=True):
                try:
                    data = json.loads(message.body)
                except Exception:
                    return
                if data.get("ref") == ref:
                    if not future.done():
                        future.set_result({"status": "ok", "ref": ref, "event": data})
        await q.consume(_consumer, no_ack=False)
        try:
            result = await asyncio.wait_for(future, timeout=opts.timeout)
            print(json.dumps(result, ensure_ascii=False))
            return 0
        except asyncio.TimeoutError:
            print(json.dumps({"status": "timeout", "ref": ref, "waited_s": opts.timeout}, ensure_ascii=False), file=sys.stderr)
            return 2

    except aio_pika.exceptions.DeliveryError as e:
        print(json.dumps({"status": "publish_returned", "reason": str(e)}, ensure_ascii=False), file=sys.stderr)
        return 3
    except Exception as e:
        print(json.dumps({"status": "error", "error": str(e)}, ensure_ascii=False), file=sys.stderr)
        return 3
    finally:
        try:
            await ch.close()
        finally:
            await conn.close()


# --------------------------------- main --------------------------------------

def main(argv: Optional[list[str]] = None) -> int:
    try:
        opts = parse_args(argv or sys.argv[1:])
    except SystemExit:
        raise
    except Exception as e:
        print(f"Invalid arguments: {e}", file=sys.stderr)
        return 4

    # uvloop (опционально)
    if os.name != "nt":
        try:
            import uvloop  # type: ignore
            uvloop.install()
        except Exception:
            pass

    return asyncio.run(send(opts))


if __name__ == "__main__":
    sys.exit(main())
