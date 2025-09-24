# ledger-core/ledger/cli/admin.py
# -*- coding: utf-8 -*-
"""
Административный CLI для ledger-core.

Зависимости: только стандартная библиотека + внутренние модули проекта.
Команды:
  settings dump [--full]           — вывести конфигурацию (JSON)
  db bootstrap --dsn DSN           — создать недостающие таблицы (репозиторий анкоринга)
  db gc-idem --dsn DSN             — GC ключей идемпотентности, вывести счётчик
  audit verify --file PATH         — верификация целостности audit JSONL
  audit send [опции]               — отправить тестовое событие в заданные синки
  anchor demo [опции]              — локальный демо-прогон: MockChain + AnchorBatcher

Коды выхода:
  0 — успех; 2 — параметры; 3 — ошибка выполнения; 4 — верификация аудита не прошла.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from typing import Any, Dict, Optional

# Внутренние зависимости
try:
    from ledger.settings import get_settings  # промышленный Settings из вашего проекта
except Exception as e:  # fallback для автономного запуска без настроек
    def get_settings():
        class _S:
            def __init__(self):
                self.meta = type("M", (), {"name": "ledger-core", "environment": os.getenv("ENV","dev"), "version": os.getenv("APP_VERSION","0.0.0")})
                self.logging = type("L", (), {"level": "INFO", "json": True})
            def configure_logging(self): 
                lvl = getattr(logging, str(os.getenv("LOG_LEVEL","INFO")).upper(), logging.INFO)
                logging.basicConfig(level=lvl, stream=sys.stderr, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
            def to_json(self, redacted=True): 
                return json.dumps({"fallback": True}, ensure_ascii=False, indent=2)
            def asdict(self, redacted=True):
                return {"fallback": True}
        return _S()

from ledger.storage.repositories.anchor_repo import AnchorRepo
from ledger.telemetry.audit_log import AuditConfig, AuditLogger, AuditVerifier, HmacSigner, ConsoleSink, RotatingFileSink, HttpSink
from ledger.anchoring.batcher import AnchorBatcher, BatcherConfig, AnchorItem
from ledger.adapters.chains.mock_chain import MockChain, MockChainConfig, InMemoryAnchorClient
# InMemoryStore соответствует интерфейсу BatcherStore
from ledger.anchoring.batcher import InMemoryStore

LOG = logging.getLogger("ledger.cli")


# ---------------------------
# Утилиты
# ---------------------------

def _setup_logging():
    """
    Инициализация логирования через настройки проекта, если доступны.
    """
    try:
        settings = get_settings()
        settings.configure_logging()
        return settings
    except Exception:
        # минимальная конфигурация
        logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
        class _S: 
            meta = type("M", (), {"name":"ledger-core","environment":os.getenv("ENV","dev"),"version":os.getenv("APP_VERSION","0.0.0")})
            def to_json(self, redacted=True): 
                return json.dumps({"fallback": True}, ensure_ascii=False, indent=2)
            def asdict(self, redacted=True): return {"fallback": True}
        return _S()


async def _run_coro(coro):
    try:
        return await coro
    except KeyboardInterrupt:
        LOG.warning("Операция прервана пользователем")
        raise SystemExit(130)
    except Exception as e:
        LOG.exception("Ошибка выполнения: %s", e)
        raise SystemExit(3)


# ---------------------------
# Команды: settings
# ---------------------------

def cmd_settings_dump(args: argparse.Namespace) -> int:
    settings = _setup_logging()
    data = settings.asdict(redacted=(not args.full))
    print(json.dumps(data, ensure_ascii=False, indent=2))
    return 0


# ---------------------------
# Команды: db
# ---------------------------

async def _db_bootstrap_async(dsn: str) -> int:
    repo = AnchorRepo.from_dsn(dsn)
    await repo.bootstrap()
    LOG.info("Схема БД для анкоринга актуальна")
    return 0

async def _db_gc_idem_async(dsn: str) -> int:
    repo = AnchorRepo.from_dsn(dsn)
    deleted = await repo.gc_idempotency()
    LOG.info("Удалено просроченных ключей идемпотентности: %d", deleted)
    print(deleted)
    return 0


# ---------------------------
# Команды: audit
# ---------------------------

async def _audit_verify_async(path: str, hmac_secret: Optional[str]) -> int:
    signer = HmacSigner(hmac_secret) if hmac_secret else None
    verifier = AuditVerifier(signer=signer)
    # Читаем потоково
    count = 0
    err: Optional[str] = None
    with open(path, "r", encoding="utf-8") as f:
        count, err = await verifier.verify_stream(f)
    if err:
        LOG.error("Верификация провалена: %s (строка #%d)", err, count)
        return 4
    LOG.info("Успешно: проверено событий %d", count)
    return 0

async def _audit_send_async(env: str, service: str, sink_console: bool, sink_file: Optional[str],
                            sink_http: Optional[str], hmac_secret: Optional[str],
                            action: str, resource: str, subject: str, tenant: Optional[str],
                            outcome: str, severity: str, reason: Optional[str],
                            attrs_json: Optional[str]) -> int:
    sinks = []
    if sink_console:
        sinks.append(ConsoleSink())
    if sink_file:
        sinks.append(RotatingFileSink(sink_file))
    if sink_http:
        sinks.append(HttpSink(sink_http))
    if not sinks:
        sinks.append(ConsoleSink())

    cfg = AuditConfig(env=env, service=service, hmac_secret=hmac_secret)
    logger = await AuditLogger.create(config=cfg, sinks=sinks)
    try:
        attrs = json.loads(attrs_json) if attrs_json else {}
        await logger.audit(
            action=action, resource=resource, subject=subject, tenant=tenant,
            outcome=outcome, severity=severity, reason=reason, attrs=attrs, force=True
        )
        await asyncio.sleep(0.1)  # дать отправить батч
    finally:
        await logger.close()
    LOG.info("Событие отправлено")
    return 0


# ---------------------------
# Команды: anchor demo
# ---------------------------

async def _anchor_demo_async(max_items: int, max_wait: float, blocks: float, count: int) -> int:
    """
    Локальная демонстрация: InMemoryStore + AnchorBatcher + MockChain.
    """
    # Запускаем мок-цепь
    chain = MockChain(MockChainConfig(block_interval_sec=blocks))
    await chain.start()
    try:
        store = InMemoryStore()
        client = InMemoryAnchorClient(fail_ratio=0.1)
        batcher = AnchorBatcher(store, client, BatcherConfig(max_items=max_items, max_wait_seconds=max_wait))
        await batcher.start()
        for i in range(count):
            item = AnchorItem(id=f"e-{i}", payload={"id": f"tx-{i}", "hash": f"{i:064x}"})
            await batcher.submit(item)
        await batcher.flush()
        await asyncio.sleep(max(blocks * 2, 1.0))  # дождаться майнинга
        await batcher.stop()
        LOG.info("Демо завершено: отправлено элементов=%d", count)
        return 0
    finally:
        await chain.stop()


# ---------------------------
# Точка входа
# ---------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ledger-admin", description="Административный CLI для ledger-core")
    p.set_defaults(func=lambda *_: 2)

    sub = p.add_subparsers(dest="cmd")

    # settings
    ps = sub.add_parser("settings", help="Работа с конфигурацией")
    pss = ps.add_subparsers(dest="subcmd")
    pssd = pss.add_parser("dump", help="Вывести текущие настройки (JSON)")
    pssd.add_argument("--full", action="store_true", help="Не редактировать секреты")
    pssd.set_defaults(func=lambda a: cmd_settings_dump(a))

    # db
    pdb = sub.add_parser("db", help="Операции с БД (репозиторий анкоринга)")
    pdbs = pdb.add_subparsers(dest="subcmd")

    pdb_boot = pdbs.add_parser("bootstrap", help="Создать недостающие таблицы")
    pdb_boot.add_argument("--dsn", required=True, help="PostgreSQL DSN, например postgresql+asyncpg://user:pass@host:5432/db")
    pdb_boot.set_defaults(func=lambda a: asyncio.run(_run_coro(_db_bootstrap_async(a.dsn))))

    pdb_gc = pdbs.add_parser("gc-idem", help="GC ключей идемпотентности")
    pdb_gc.add_argument("--dsn", required=True)
    pdb_gc.set_defaults(func=lambda a: asyncio.run(_run_coro(_db_gc_idem_async(a.dsn))))

    # audit
    pa = sub.add_parser("audit", help="Операции аудита")
    pas = pa.add_subparsers(dest="subcmd")

    pav = pas.add_parser("verify", help="Проверить целостность audit JSONL")
    pav.add_argument("--file", required=True)
    pav.add_argument("--hmac-secret", default=os.getenv("AUDIT_HMAC"), help="Секрет HMAC, если события подписаны")
    pav.set_defaults(func=lambda a: asyncio.run(_run_coro(_audit_verify_async(a.file, a.hmac_secret))))

    pasend = pas.add_parser("send", help="Отправить тестовое событие")
    pasend.add_argument("--env", default=os.getenv("ENV","dev"))
    pasend.add_argument("--service", default="ledger-core")
    pasend.add_argument("--sink-console", action="store_true", help="Писать в stdout")
    pasend.add_argument("--sink-file", help="Путь к файлу JSONL")
    pasend.add_argument("--sink-http", help="HTTP endpoint (application/x-ndjson)")
    pasend.add_argument("--hmac-secret", default=os.getenv("AUDIT_HMAC"))
    pasend.add_argument("--action", required=True)
    pasend.add_argument("--resource", required=True)
    pasend.add_argument("--subject", required=True)
    pasend.add_argument("--tenant")
    pasend.add_argument("--outcome", default="success", choices=["success","failure","deny"])
    pasend.add_argument("--severity", default="info", choices=["info","notice","warning","error","critical"])
    pasend.add_argument("--reason")
    pasend.add_argument("--attrs-json", help='Доп. атрибуты, JSON, например: \'{"k":"v"}\'')
    pasend.set_defaults(func=lambda a: asyncio.run(_run_coro(_audit_send_async(
        a.env, a.service, a.sink_console, a.sink_file, a.sink_http, a.hmac_secret,
        a.action, a.resource, a.subject, a.tenant, a.outcome, a.severity, a.reason, a.attrs_json
    ))))

    # anchor demo
    pan = sub.add_parser("anchor", help="Операции анкоринга")
    pans = pan.add_subparsers(dest="subcmd")

    demo = pans.add_parser("demo", help="Локальная демонстрация анкоринга (MockChain + AnchorBatcher)")
    demo.add_argument("--max-items", type=int, default=8, help="Макс. элементов в батче")
    demo.add_argument("--max-wait", type=float, default=1.0, help="Макс. ожидание батча, сек")
    demo.add_argument("--blocks", type=float, default=0.5, help="Интервал блоков, сек")
    demo.add_argument("--count", type=int, default=25, help="Количество элементов для отправки")
    demo.set_defaults(func=lambda a: asyncio.run(_run_coro(_anchor_demo_async(a.max_items, a.max_wait, a.blocks, a.count))))

    return p


def main(argv: Optional[list[str]] = None) -> int:
    settings = _setup_logging()  # логирование
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):  # нет подкоманды
        parser.print_help()
        return 2
    try:
        return int(args.func(args))  # func может вернуть код или бросить исключение
    except SystemExit as e:
        return int(e.code)
    except Exception as e:
        LOG.exception("Неожиданная ошибка: %s", e)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
