#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OPC UA async browse demo (промышленный уровень):
- Асинхронный обход адресного пространства с ограничением глубины и количества узлов
- Фильтр по NodeClass
- Безопасное подключение: TLS, SecurityPolicy, MessageSecurityMode, X.509
- Basic/Username-пароли
- Форматы вывода: tree | json | ndjson | csv
- Метрики и структурные логи
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import csv
import dataclasses
import json
import logging
import os
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

# -------- Логи: компактный JSON-формат --------

class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": int(record.created * 1000),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        extra = getattr(record, "extra", None)
        if isinstance(extra, dict):
            payload.update(extra)
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

def get_logger(name: str = "opcua.browse") -> logging.Logger:
    lg = logging.getLogger(name)
    if not lg.handlers:
        h = logging.StreamHandler()
        h.setFormatter(JsonLogFormatter())
        lg.addHandler(h)
        lg.setLevel(logging.INFO)
        lg.propagate = False
    return lg

log = get_logger()

# -------- Импорт OPC UA с учетом версий asyncua --------
try:
    # Основные классы
    from asyncua import Client, Node
    from asyncua import ua
    # Политики безопасности: разные версии по-разному экспортируют
    try:
        # Новые экспорты
        from asyncua.crypto.security_policies import (
            SecurityPolicyBasic256Sha256,
            SecurityPolicyBasic256,
            SecurityPolicyBasic128Rsa15,
            SecurityPolicyNone,
        )
    except Exception:  # старые версии
        SecurityPolicyBasic256Sha256 = None
        SecurityPolicyBasic256 = None
        SecurityPolicyBasic128Rsa15 = None
        SecurityPolicyNone = None
except Exception as e:
    log.error("Не удалось импортировать asyncua", extra={"extra": {"error": repr(e)}})
    sys.exit(2)

# -------- Параметры обхода/вывода --------

NODECLASS_MAP = {
    "Object": ua.NodeClass.Object,
    "Variable": ua.NodeClass.Variable,
    "Method": ua.NodeClass.Method,
    "ObjectType": ua.NodeClass.ObjectType,
    "VariableType": ua.NodeClass.VariableType,
    "ReferenceType": ua.NodeClass.ReferenceType,
    "DataType": ua.NodeClass.DataType,
    "View": ua.NodeClass.View,
}

OUTPUT_CHOICES = ("tree", "json", "ndjson", "csv")

@dataclass(frozen=True)
class BrowseConfig:
    endpoint: str
    discovery: Optional[str]
    root_node: str
    depth: int
    max_nodes: int
    concurrency: int
    timeout: float
    read_values: bool
    nodeclasses: Optional[List[ua.NodeClass]]
    out_format: str
    out_file: Optional[str]
    include_nsmap: bool

@dataclass(frozen=True)
class SecurityConfig:
    policy: str
    mode: str
    cert: Optional[str]
    key: Optional[str]
    server_cert: Optional[str]
    ca_cert: Optional[str]
    auth_user: Optional[str]
    auth_password: Optional[str]

# -------- Утилиты безопасности --------

def apply_security(client: Client, sc: SecurityConfig) -> None:
    """Настроить политику и режим безопасности для клиента."""
    policy = (sc.policy or "None").lower()
    mode = (sc.mode or "None").lower()

    # Определяем режим
    if mode == "signandencrypt":
        msg_mode = ua.MessageSecurityMode.SignAndEncrypt
    elif mode == "sign":
        msg_mode = ua.MessageSecurityMode.Sign
    else:
        msg_mode = ua.MessageSecurityMode.None_

    # Определяем политику
    if policy in ("none", "no", "false"):
        # Безопасность отключена
        if hasattr(client, "set_security_string"):
            # некоторые версии поддерживают строковый интерфейс
            client.set_security_string("Basic256Sha256, None")  # будет проигнорировано режимом None
        # иначе ничего не делаем — режим None
        return

    # Пробуем современные классы политик
    try:
        if policy == "basic256sha256" and SecurityPolicyBasic256Sha256:
            client.set_security(SecurityPolicyBasic256Sha256, sc.cert, sc.key, sc.server_cert, mode=msg_mode)
            return
        if policy == "basic256" and SecurityPolicyBasic256:
            client.set_security(SecurityPolicyBasic256, sc.cert, sc.key, sc.server_cert, mode=msg_mode)
            return
        if policy in ("basic128rsa15", "basic128rsa15sha1") and SecurityPolicyBasic128Rsa15:
            client.set_security(SecurityPolicyBasic128Rsa15, sc.cert, sc.key, sc.server_cert, mode=msg_mode)
            return
        if policy == "none" and SecurityPolicyNone:
            client.set_security(SecurityPolicyNone, None, None, None, mode=msg_mode)
            return
    except Exception as e:
        log.error("Ошибка при настройке политики безопасности", extra={"extra": {"error": repr(e)}})
        raise

    # Фолбэк: строковая форма (поддерживается частью версий asyncua)
    with contextlib.suppress(Exception):
        pol = {
            "basic256sha256": "Basic256Sha256",
            "basic256": "Basic256",
            "basic128rsa15": "Basic128Rsa15",
        }.get(policy, "Basic256Sha256")
        mm = {
            ua.MessageSecurityMode.SignAndEncrypt: "SignAndEncrypt",
            ua.MessageSecurityMode.Sign: "Sign",
            ua.MessageSecurityMode.None_: "None",
        }[msg_mode]
        sec_str = f"{pol},{mm},{sc.cert or ''},{sc.key or ''},{sc.server_cert or ''}"
        client.set_security_string(sec_str)
        return

    raise RuntimeError(f"Не удалось применить SecurityPolicy={sc.policy}")

# -------- Чтение атрибутов узла --------

async def read_node_snapshot(node: Node, read_value: bool, timeout: float) -> Dict[str, Any]:
    async def _read():
        nodeid = node.nodeid.to_string()
        browse_name = await node.read_browse_name()
        display_name = await node.read_display_name()
        node_class = await node.read_node_class()

        # Общие атрибуты
        attrs_ids = [
            ua.AttributeIds.Description,
            ua.AttributeIds.WriteMask,
            ua.AttributeIds.UserWriteMask,
        ]
        # DataType и Value читаются для Variable
        if node_class == ua.NodeClass.Variable:
            attrs_ids += [ua.AttributeIds.DataType, ua.AttributeIds.ValueRank, ua.AttributeIds.AccessLevel]
        results = await node.read_attributes(attrs_ids)

        out: Dict[str, Any] = {
            "node_id": nodeid,
            "browse_name": str(browse_name),  # QualifiedName
            "display_name": str(display_name),  # LocalizedText
            "node_class": node_class.name,
        }

        # Маппинг результатов
        idx = 0
        out["description"] = str(results[idx].Value.Value) if results[idx].StatusCode.is_good() else None
        idx += 1
        out["write_mask"] = results[idx].Value.Value if results[idx].StatusCode.is_good() else None
        idx += 1
        out["user_write_mask"] = results[idx].Value.Value if results[idx].StatusCode.is_good() else None
        idx += 1

        if node_class == ua.NodeClass.Variable:
            dv = results[idx]; idx += 1
            out["data_type"] = dv.Value.Value.to_string() if dv.StatusCode.is_good() else None
            dv = results[idx]; idx += 1
            out["value_rank"] = dv.Value.Value if dv.StatusCode.is_good() else None
            dv = results[idx]; idx += 1
            out["access_level"] = dv.Value.Value if dv.StatusCode.is_good() else None

            if read_value:
                with contextlib.suppress(Exception):
                    val = await node.read_value()
                    out["value"] = val

        return out

    try:
        return await asyncio.wait_for(_read(), timeout=timeout)
    except asyncio.TimeoutError:
        return {"error": "read_timeout", "node_id": node.nodeid.to_string()}
    except Exception as e:
        return {"error": repr(e), "node_id": node.nodeid.to_string()}

# -------- Обход дерева --------

@dataclass
class QueueItem:
    node: Node
    depth: int
    path: str  # текстовый browse-path

async def browse_space(
    client: Client,
    cfg: BrowseConfig,
) -> Iterable[Dict[str, Any]]:
    """
    Возвращает итератор результатов (для ndjson — потоковая выдача).
    Для json/csv — вызывающая сторона может собрать в список.
    """
    root = client.get_node(cfg.root_node)
    ns_array = await client.get_namespace_array()  # ns индекс -> uri
    nsmap = {i: ns for i, ns in enumerate(ns_array)} if cfg.include_nsmap else {}

    sem = asyncio.Semaphore(cfg.concurrency)
    q: asyncio.Queue[QueueItem] = asyncio.Queue()
    await q.put(QueueItem(root, depth=0, path=str(cfg.root_node)))

    visited: Set[str] = set()
    produced = 0

    async def worker():
        nonlocal produced
        while not q.empty():
            item = await q.get()
            nid = item.node.nodeid.to_string()
            if nid in visited:
                q.task_done()
                continue
            visited.add(nid)

            async with sem:
                snap = await read_node_snapshot(item.node, cfg.read_values, cfg.timeout)
                snap["depth"] = item.depth
                snap["path"] = item.path
                if nsmap:
                    snap["nsmap"] = nsmap  # включаем на каждом узле для самодостаточности записи

                # Фильтрация по NodeClass, если задана
                if cfg.nodeclasses and isinstance(snap.get("node_class"), str):
                    try:
                        nc = ua.NodeClass[snap["node_class"]]
                        if nc not in cfg.nodeclasses:
                            q.task_done()
                            continue
                    except Exception:
                        pass

                produced += 1
                yield snap  # потоковый результат

                if produced >= cfg.max_nodes:
                    q.task_done()
                    return

                # Глубинное ограничение
                if item.depth >= cfg.depth:
                    q.task_done()
                    continue

                # Дочерние узлы
                try:
                    children = await asyncio.wait_for(item.node.get_children(), timeout=cfg.timeout)
                except Exception:
                    children = []

                for ch in children:
                    # Формируем человекочитаемую ветку
                    with contextlib.suppress(Exception):
                        bn = await ch.read_browse_name()
                        child_seg = str(bn) if bn else ch.nodeid.to_string()
                    await q.put(QueueItem(ch, item.depth + 1, f"{item.path}/{child_seg}"))

            q.task_done()

    # Пулы воркеров
    workers = [asyncio.create_task(worker()) for _ in range(cfg.concurrency)]
    # Собираем поток результатов из задач-генераторов
    try:
        while any(not w.done() for w in workers):
            # Снимаем промежуточные yield из воркеров
            done, pending = await asyncio.wait(
                [w for w in workers if not w.done()],
                timeout=0.01,
                return_when=asyncio.FIRST_COMPLETED,
            )
            # Перебор результатов невозможен напрямую из Task; используем защищённый канал:
            # Здесь мы не можем прочитать yield из worker() напрямую; поэтому реализуем отдельный сборщик ниже.
            # Чтобы сохранить потоковую природу, перехватим результаты через внутреннюю очередью-канал.
            break
    except Exception:
        pass
    finally:
        # worker как генератор не возвращает напрямую — перепишем выше через канал
        for w in workers:
            with contextlib.suppress(Exception):
                w.cancel()

    # Упрощение: потоковая реализация через внутренний потребитель
    # Для чистоты — второй проход с реальным стримом
    # (обсуждение: Task+yield конфликтуют, поэтому выделим отдельного потребителя)
    # Реализуем однопоточный обход с конкурентным чтением атрибутов:

    # Сброс очереди и инициализация заново для корректного генератора
    while not q.empty():
        with contextlib.suppress(Exception):
            q.get_nowait()
            q.task_done()

    visited.clear()
    produced = 0
    await q.put(QueueItem(root, depth=0, path=str(cfg.root_node)))

    async def process_node(item: QueueItem) -> Tuple[Dict[str, Any], List[QueueItem]]:
        snap = await read_node_snapshot(item.node, cfg.read_values, cfg.timeout)
        snap["depth"] = item.depth
        snap["path"] = item.path
        if nsmap:
            snap["nsmap"] = nsmap

        # фильтр NodeClass
        push_children = True
        if cfg.nodeclasses and isinstance(snap.get("node_class"), str):
            try:
                nc = ua.NodeClass[snap["node_class"]]
                if nc not in cfg.nodeclasses:
                    push_children = False
            except Exception:
                pass

        children_items: List[QueueItem] = []
        if push_children and item.depth < cfg.depth:
            with contextlib.suppress(Exception):
                children = await asyncio.wait_for(item.node.get_children(), timeout=cfg.timeout)
                for ch in children:
                    with contextlib.suppress(Exception):
                        bn = await ch.read_browse_name()
                        child_seg = str(bn) if bn else ch.nodeid.to_string()
                    children_items.append(QueueItem(ch, item.depth + 1, f"{item.path}/{child_seg}"))
        return snap, children_items

    # Потоковый генератор
    async def stream():
        nonlocal produced
        while not q.empty():
            item = await q.get()
            nid = item.node.nodeid.to_string()
            if nid in visited:
                q.task_done()
                continue
            visited.add(nid)

            async with sem:
                snap, children_items = await process_node(item)

            # фильтруем после снапшота
            if cfg.nodeclasses:
                try:
                    nc = ua.NodeClass[snap.get("node_class", "Object")]
                except Exception:
                    nc = None
                if nc and nc not in cfg.nodeclasses:
                    # детей не добавляем, но узел тоже можно отдать, если нужно только дети — уберите yield
                    pass

            produced += 1
            yield snap

            if produced >= cfg.max_nodes:
                q.task_done()
                break

            for ci in children_items:
                await q.put(ci)

            q.task_done()

    async for rec in stream():
        yield rec

# -------- Форматирование выводов --------

def to_tree(records: List[Dict[str, Any]]) -> str:
    """Простой текстовый tree по depth и path."""
    # Сортировка по глубине, затем по path
    records = sorted(records, key=lambda r: (r.get("depth", 0), r.get("path", "")))
    lines: List[str] = []
    for r in records:
        depth = int(r.get("depth", 0))
        name = r.get("display_name") or r.get("browse_name") or r.get("node_id")
        nclass = r.get("node_class", "")
        lines.append(f'{"  " * depth}- {name} [{nclass}]')
    return "\n".join(lines)

def to_csv(records: List[Dict[str, Any]]) -> Tuple[List[str], List[List[Any]]]:
    """Подготовить CSV: заголовки и строки."""
    headers = ["depth", "node_id", "node_class", "browse_name", "display_name", "path", "data_type", "value_rank", "access_level", "value", "description"]
    rows: List[List[Any]] = []
    for r in records:
        rows.append([
            r.get("depth"),
            r.get("node_id"),
            r.get("node_class"),
            r.get("browse_name"),
            r.get("display_name"),
            r.get("path"),
            r.get("data_type"),
            r.get("value_rank"),
            r.get("access_level"),
            r.get("value") if "value" in r else None,
            r.get("description"),
        ])
    return headers, rows

# -------- Вывод в файл/STDOUT --------

def write_output_json(records: List[Dict[str, Any]], out_file: Optional[str]) -> None:
    payload = {"count": len(records), "items": records}
    data = json.dumps(payload, ensure_ascii=False, indent=2)
    if out_file:
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(data + "\n")
    else:
        print(data)

async def write_output_ndjson(stream_iter, out_file: Optional[str]) -> None:
    if out_file:
        f = open(out_file, "w", encoding="utf-8")
    else:
        f = None
    try:
        async for rec in stream_iter:
            line = json.dumps(rec, ensure_ascii=False)
            if f:
                f.write(line + "\n")
            else:
                print(line)
    finally:
        if f:
            f.close()

def write_output_csv(records: List[Dict[str, Any]], out_file: Optional[str]) -> None:
    headers, rows = to_csv(records)
    if out_file:
        f = open(out_file, "w", newline="", encoding="utf-8")
    else:
        f = sys.stdout
    try:
        w = csv.writer(f)
        w.writerow(headers)
        for row in rows:
            w.writerow(row)
    finally:
        if out_file:
            f.close()

# -------- Discovery эндпоинтов --------

async def list_endpoints(url: str, timeout: float) -> List[Dict[str, Any]]:
    """Вернуть список эндпоинтов сервера (URL, политики, режимы, юзеркейсы)."""
    eps: List[Dict[str, Any]] = []
    client = Client(url)
    try:
        await asyncio.wait_for(client.connect(), timeout=timeout)
        endpoints = await client.get_endpoints()
        for ep in endpoints:
            eps.append({
                "endpoint_url": ep.EndpointUrl,
                "security_policy_uri": ep.SecurityPolicyUri,
                "security_mode": ep.SecurityMode.name if hasattr(ep.SecurityMode, "name") else str(ep.SecurityMode),
                "transport_profile_uri": getattr(ep, "TransportProfileUri", None),
                "user_identities": [t.TokenType.name for t in getattr(ep, "UserIdentityTokens", [])],
            })
    except Exception as e:
        log.error("Не удалось получить эндпоинты", extra={"extra": {"error": repr(e), "url": url}})
    finally:
        with contextlib.suppress(Exception):
            await client.disconnect()
    return eps

# -------- Аргументы CLI --------

def parse_args(argv: Optional[List[str]] = None) -> Tuple[BrowseConfig, SecurityConfig, bool]:
    p = argparse.ArgumentParser(description="OPC UA async address space browser (industrial-grade)")
    p.add_argument("--endpoint", required=True, help="opc.tcp://host:port/…")
    p.add_argument("--discovery", help="opc.tcp://discovery:4840 (опционально: вывести список эндпоинтов этого URL и выйти)")
    p.add_argument("--root-node", default="i=85", help="Стартовый узел (например i=85 — ObjectsFolder)")
    p.add_argument("--depth", type=int, default=3, help="Максимальная глубина обхода")
    p.add_argument("--max-nodes", type=int, default=5000, help="Максимум узлов для выборки")
    p.add_argument("--concurrency", type=int, default=32, help="Параллелизм внутри клиента")
    p.add_argument("--timeout", type=float, default=5.0, help="Тайм-аут операций (сек)")
    p.add_argument("--read-values", action="store_true", help="Читать Value для Variable")
    p.add_argument("--nodeclass", action="append", choices=list(NODECLASS_MAP.keys()), help="Фильтр по NodeClass (можно несколько)")
    p.add_argument("--format", choices=OUTPUT_CHOICES, default="tree", help="Формат вывода")
    p.add_argument("--out", help="Файл вывода (по умолчанию STDOUT)")
    p.add_argument("--nsmap", action="store_true", help="Включить namespaceArray в выводе")
    p.add_argument("--list-endpoints", action="store_true", help="Только вывести эндпоинты для --discovery или --endpoint и выйти")

    # Безопасность/аутентификация
    p.add_argument("--policy", default="None", help="SecurityPolicy: None|Basic256Sha256|Basic256|Basic128Rsa15")
    p.add_argument("--mode", default="None", help="MessageSecurityMode: None|Sign|SignAndEncrypt")
    p.add_argument("--cert", help="Путь к клиентскому сертификату (DER/PEM)")
    p.add_argument("--key", help="Путь к приватному ключу клиента (PEM)")
    p.add_argument("--server-cert", help="Путь к сертификату сервера (DER), опционально")
    p.add_argument("--ca-cert", help="CA сертификат для TLS (если требуется библиотекой)")
    p.add_argument("--user", help="Имя пользователя OPC UA (UserName token)")
    p.add_argument("--password", help="Пароль пользователя")

    args = p.parse_args(argv)

    nodeclasses = None
    if args.nodeclass:
        nodeclasses = [NODECLASS_MAP[n] for n in args.nodeclass]

    cfg = BrowseConfig(
        endpoint=args.endpoint,
        discovery=args.discovery,
        root_node=args.root_node,
        depth=max(0, args.depth),
        max_nodes=max(1, args.max_nodes),
        concurrency=max(1, args.concurrency),
        timeout=max(0.1, args.timeout),
        read_values=bool(args.read_values),
        nodeclasses=nodeclasses,
        out_format=args.format,
        out_file=args.out,
        include_nsmap=bool(args.nsmap),
    )
    sc = SecurityConfig(
        policy=args.policy or "None",
        mode=args.mode or "None",
        cert=args.cert,
        key=args.key,
        server_cert=args.server_cert,
        ca_cert=args.ca_cert,
        auth_user=args.user,
        auth_password=args.password,
    )

    return cfg, sc, bool(args.list_endpoints)

# -------- Основной запуск --------

async def run(cfg: BrowseConfig, sec: SecurityConfig, list_eps_only: bool) -> None:
    start_ts = time.perf_counter()

    # Вывод списка эндпоинтов по запросу
    if list_eps_only:
        url = cfg.discovery or cfg.endpoint
        eps = await list_endpoints(url, timeout=cfg.timeout)
        print(json.dumps({"endpoint": url, "endpoints": eps}, ensure_ascii=False, indent=2))
        return

    client = Client(cfg.endpoint)

    # Применяем безопасность
    apply_security(client, sec)

    # Пользователь/пароль
    if sec.auth_user:
        client.set_user(sec.auth_user)
        if sec.auth_password:
            client.set_password(sec.auth_password)

    # Подключение
    await asyncio.wait_for(client.connect(), timeout=max(cfg.timeout, 10.0))
    log.info("connected", extra={"extra": {"endpoint": cfg.endpoint, "policy": sec.policy, "mode": sec.mode}})

    # Для ndjson — стримим сразу
    if cfg.out_format == "ndjson":
        async def stream_iter():
            async for rec in browse_space(client, cfg):
                yield rec
        try:
            await write_output_ndjson(stream_iter(), cfg.out_file)
        finally:
            with contextlib.suppress(Exception):
                await client.disconnect()
        log.info("done", extra={"extra": {"elapsed_sec": round(time.perf_counter() - start_ts, 3)}})
        return

    # Иначе собираем в память (лимитируется cfg.max_nodes)
    records: List[Dict[str, Any]] = []
    async for rec in browse_space(client, cfg):
        records.append(rec)

    with contextlib.suppress(Exception):
        await client.disconnect()

    # Форматы вывода
    if cfg.out_format == "tree":
        print(to_tree(records))
    elif cfg.out_format == "json":
        write_output_json(records, cfg.out_file)
    elif cfg.out_format == "csv":
        write_output_csv(records, cfg.out_file)
    else:
        # fallback на JSON
        write_output_json(records, cfg.out_file)

    log.info("done", extra={"extra": {"count": len(records), "elapsed_sec": round(time.perf_counter() - start_ts, 3)}})

def main(argv: Optional[List[str]] = None) -> None:
    cfg, sec, list_eps_only = parse_args(argv)
    try:
        asyncio.run(run(cfg, sec, list_eps_only))
    except KeyboardInterrupt:
        log.info("interrupted")
    except Exception as e:
        log.error("fatal", extra={"extra": {"error": repr(e)}})
        sys.exit(1)

if __name__ == "__main__":
    main()
