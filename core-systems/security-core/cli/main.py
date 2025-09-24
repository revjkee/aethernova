#!/usr/bin/env python3
# security-core/cli/main.py
# Универсальный CLI для security-core.
# Зависимости: стандартная библиотека.
# Опциональные зависимости (подхватываются, если установлены): PyYAML, google-cloud-kms, prometheus_client.
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import textwrap
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple, Union

# --- Опциональный YAML ---
try:
    import yaml  # type: ignore
except Exception:  # noqa: BLE001
    yaml = None  # type: ignore

# --- Внутренние зависимости security-core ---
# Важно: структура пакетов должна соответствовать вашему дереву исходников.
from security.utils.time import (
    now_utc,
    epoch_milliseconds,
    parse_rfc3339,
    format_rfc3339,
    parse_duration,
    format_duration,
    window_bounds,
)
from security.authz.policy_adapter import PolicyAdapter
from security.iam.groups import (
    InMemoryGroupRepository,
    GroupService,
    MemberRef,
    GroupsConfig,
    Group,
)
from security.kms.gcp_kms import (
    GcpKmsClient,
    KmsConfig,
    GcpKeyRef,
    NotAvailable as KmsNotAvailable,
    DependencyMissing as KmsDependencyMissing,
    KmsError,
)
from security.pki.crl import CRLManager, CRLConfig, CRLError
from security.threat_detection.detectors import (
    DetectorEngine,
    brute_force_factory,
    impossible_travel_factory,
    rare_country_factory,
    token_replay_factory,
    suspicious_nomfa_factory,
    priv_esc_factory,
    anomalous_download_factory,
    SecurityEvent,
)

# =========================
# Константы и утилиты
# =========================

EXIT_OK = 0
EXIT_BADARGS = 2
EXIT_RUNTIME = 10
EXIT_CONFIG = 12
EXIT_NOTFOUND = 14
EXIT_UNAVAILABLE = 16

LOG = logging.getLogger("security-core.cli")


def setup_logging(level: str = "INFO") -> None:
    lvl = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=lvl,
        format="%(asctime)s.%(msecs)03dZ %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    # UTC timestamps
    logging.Formatter.converter = lambda *args: datetime.now(timezone.utc).timetuple()


def read_structured(path: Optional[str]) -> Any:
    """
    Читает JSON/NDJSON/YAML в зависимости от расширения.
    - .json  : JSON объект/массив
    - .ndjson: список объектов (строка на объект)
    - .yaml/.yml: при наличии PyYAML
    Если path=None или "-", читает из stdin (по умолчанию JSON).
    """
    data = None
    if not path or path == "-":
        buf = sys.stdin.read()
        # попытаемся распознать ndjson (несколько строк JSON)
        if "\n" in buf.strip():
            lines = [ln for ln in buf.splitlines() if ln.strip()]
            try:
                return [json.loads(ln) for ln in lines]
            except Exception:
                pass
        return json.loads(buf) if buf.strip() else None

    ext = os.path.splitext(path)[1].lower()
    with open(path, "r", encoding="utf-8") as f:
        if ext == ".json":
            data = json.load(f)
        elif ext == ".ndjson":
            data = [json.loads(ln) for ln in f if ln.strip()]
        elif ext in (".yaml", ".yml"):
            if not yaml:
                raise RuntimeError("YAML support is not available (PyYAML not installed)")
            data = yaml.safe_load(f)
        else:
            # default JSON
            data = json.load(f)
    return data


def write_json(obj: Any, *, pretty: bool = False, ndjson: bool = False) -> None:
    if ndjson and isinstance(obj, list):
        for item in obj:
            sys.stdout.write(json.dumps(item, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n")
        sys.stdout.flush()
        return
    if pretty:
        json.dump(obj, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
    else:
        json.dump(obj, sys.stdout, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    sys.stdout.write("\n")
    sys.stdout.flush()


def load_policies(paths: List[str]) -> List[Mapping[str, Any]]:
    """
    Загружает политики из списка путей (JSON/YAML). NDJSON поддерживается (каждая строка — политика).
    """
    out: List[Mapping[str, Any]] = []
    for p in paths:
        data = read_structured(p)
        if data is None:
            continue
        if isinstance(data, list):
            for it in data:
                if isinstance(it, dict):
                    out.append(it)
        elif isinstance(data, dict):
            out.append(data)
        else:
            raise RuntimeError(f"Unsupported policy file content type: {type(data)}")
    return out


# =========================
# Подкоманда: authz
# =========================

def cmd_authz_evaluate(args: argparse.Namespace) -> int:
    """
    Оценка запроса авторизации.
    """
    adapter = PolicyAdapter()

    policies = load_policies(args.policies or [])
    if not policies:
        LOG.error("Не найдено ни одной политики")
        return EXIT_CONFIG

    bundle = adapter.compile_bundle(args.tenant, policies)

    # Загрузка запроса
    req = read_structured(args.request)
    if not isinstance(req, dict):
        LOG.error("Некорректный формат запроса (ожидается JSON-объект)")
        return EXIT_BADARGS

    subject = req.get("subject", {})
    resource = req.get("resource", {})
    action = req.get("action")
    session = req.get("session", {})
    env = req.get("env", {})

    if not action:
        LOG.error("Поле 'action' обязательно")
        return EXIT_BADARGS

    res = adapter.evaluate(
        args.tenant,
        subject=subject,
        resource=resource,
        action=action,
        session=session,
        env=env,
        include_explanation=args.explain,
        include_obligations=True,
        policy_names=args.policies_names,
    )

    write_json(
        {
            "decision": res.decision,
            "obligations": [o.__dict__ for o in res.obligations],
            "explanation": res.explanation.__dict__ if res.explanation else None,
            "bundle_etag": res.bundle_etag or bundle.etag,
        },
        pretty=args.pretty,
    )
    return EXIT_OK


# =========================
# Подкоманда: iam (groups snapshot management)
# =========================

def _load_groups_repo(snapshot_path: Optional[str]) -> Tuple[InMemoryGroupRepository, GroupService]:
    repo = InMemoryGroupRepository()
    svc = GroupService(repo, cfg=GroupsConfig())
    if snapshot_path and os.path.exists(snapshot_path):
        data = read_structured(snapshot_path)
        if data and isinstance(data, dict) and data.get("tenant_id"):
            # импорт снапшота
            from security.iam.groups import GroupSnapshot
            snap = GroupSnapshot(**data)
            svc.import_snapshot(snap, overwrite=True)
    return repo, svc


def _save_groups_repo(svc: GroupService, tenant: str, snapshot_path: Optional[str]) -> None:
    if not snapshot_path:
        return
    snap = svc.export_snapshot(tenant)
    with open(snapshot_path, "w", encoding="utf-8") as f:
        json.dump(json.loads(snap.json()), f, ensure_ascii=False, indent=2, sort_keys=True)


def cmd_iam_groups(args: argparse.Namespace) -> int:
    """
    Управление группами через файл-снапшот (без постоянной БД).
    """
    repo, svc = _load_groups_repo(args.snapshot)
    tenant = args.tenant

    try:
        if args.op == "list":
            items, _ = svc.list_groups(tenant, prefix=args.prefix, limit=args.limit)
            write_json([g.dict() for g in items], pretty=args.pretty)
            return EXIT_OK

        elif args.op == "create":
            g = svc.create_group(
                tenant_id=tenant,
                group_id=args.group_id,
                display_name=args.display_name,
                description=args.description,
                labels=json.loads(args.labels) if args.labels else None,
                attributes=json.loads(args.attributes) if args.attributes else None,
                roles=args.roles or [],
                members=[MemberRef(**m) for m in (read_structured(args.members) or [])] if args.members else [],
            )
            _save_groups_repo(svc, tenant, args.snapshot)
            write_json(g.dict(), pretty=args.pretty)
            return EXIT_OK

        elif args.op == "delete":
            g = svc.get_group(tenant, args.group_id)
            svc.delete_group(tenant, args.group_id, expect_etag=g.etag if not args.force else None)
            _save_groups_repo(svc, tenant, args.snapshot)
            write_json({"deleted": args.group_id}, pretty=args.pretty)
            return EXIT_OK

        elif args.op == "members":
            add = [MemberRef(**m) for m in (read_structured(args.add) or [])] if args.add else []
            rem = [MemberRef(**m) for m in (read_structured(args.remove) or [])] if args.remove else []
            g = svc.get_group(tenant, args.group_id)
            if add:
                g = svc.add_members(tenant, args.group_id, add, expect_etag=g.etag if not args.force else None)
            if rem:
                g = svc.remove_members(tenant, args.group_id, rem, expect_etag=g.etag if not args.force else None)
            _save_groups_repo(svc, tenant, args.snapshot)
            write_json(g.dict(), pretty=args.pretty)
            return EXIT_OK

        else:
            LOG.error("Неизвестная операция для groups")
            return EXIT_BADARGS

    except Exception as e:  # noqa: BLE001
        LOG.exception("Ошибка IAM")
        write_json({"error": str(e)}, pretty=args.pretty)
        return EXIT_RUNTIME


# =========================
# Подкоманда: kms (GCP KMS)
# =========================

def _kms_client_from_args(args: argparse.Namespace) -> GcpKmsClient:
    cfg = KmsConfig(
        default_key=GcpKmsClient.key_ref(*args.default_key.split("/")) if args.default_key else None,  # expects "project/location/ring/key"
        timeout_seconds=args.timeout,
        max_attempts=args.max_attempts,
        user_agent_suffix="aethernova-security-core/cli",
    )
    return GcpKmsClient(cfg)


def _parse_keyref(s: str) -> GcpKeyRef:
    # ожидается "projects/P/locations/L/keyRings/R/cryptoKeys/K" (или с /cryptoKeyVersions/N)
    if s.startswith("projects/"):
        return GcpKeyRef(resource=s)
    # краткая форма: project/location/ring/key
    parts = s.split("/")
    if len(parts) == 4:
        return GcpKmsClient.key_ref(*parts)
    if len(parts) == 5:
        project, location, ring, key, ver = parts
        return GcpKmsClient.key_version_ref(project, location, ring, key, ver)
    raise ValueError("invalid key reference format")


def cmd_kms(args: argparse.Namespace) -> int:
    try:
        kms = _kms_client_from_args(args)
    except (KmsNotAvailable, KmsDependencyMissing) as e:
        write_json({"error": str(e)}, pretty=args.pretty)
        return EXIT_UNAVAILABLE
    except Exception as e:  # noqa: BLE001
        LOG.exception("Ошибка инициализации KMS")
        write_json({"error": str(e)}, pretty=args.pretty)
        return EXIT_CONFIG

    try:
        if args.op == "encrypt":
            data: bytes
            if args.input and args.input != "-":
                with open(args.input, "rb") as f:
                    data = f.read()
            else:
                data = sys.stdin.buffer.read()
            key = _parse_keyref(args.key) if args.key else None
            aad = json.loads(args.aad) if args.aad else None
            env = kms.encrypt_bytes(data, key=key, aad=aad)
            sys.stdout.buffer.write(env)
            if sys.stdout.isatty():
                sys.stdout.write("\n")
            return EXIT_OK

        if args.op == "decrypt":
            blob: bytes
            if args.input and args.input != "-":
                with open(args.input, "rb") as f:
                    blob = f.read()
            else:
                blob = sys.stdin.buffer.read()
            aad = json.loads(args.aad) if args.aad else None
            pt = kms.decrypt_bytes(blob, aad=aad)
            sys.stdout.buffer.write(pt)
            if sys.stdout.isatty():
                sys.stdout.write("\n")
            return EXIT_OK

        if args.op == "sign":
            data = sys.stdin.buffer.read() if not args.input or args.input == "-" else open(args.input, "rb").read()
            from cryptography.hazmat.primitives import hashes
            h = hashes.Hash(getattr(hashes, args.hash_alg)())
            h.update(data)
            digest = h.finalize()
            sig = kms.sign_digest(key_version=_parse_keyref(args.key_version), digest=digest, hash_alg=args.hash_alg)
            sys.stdout.buffer.write(sig)
            if sys.stdout.isatty():
                sys.stdout.write("\n")
            return EXIT_OK

        if args.op == "verify":
            data = sys.stdin.buffer.read() if not args.input or args.input == "-" else open(args.input, "rb").read()
            sig = sys.stdin.buffer.read() if not args.signature or args.signature == "-" else open(args.signature, "rb").read()
            from cryptography.hazmat.primitives import hashes
            h = hashes.Hash(getattr(hashes, args.hash_alg)()); h.update(data); digest = h.finalize()
            ok = kms.verify_signature(key_version=_parse_keyref(args.key_version), digest=digest, signature=sig, hash_alg=args.hash_alg)
            write_json({"verified": bool(ok)}, pretty=args.pretty)
            return EXIT_OK if ok else EXIT_RUNTIME

        write_json({"error": "unsupported kms op"}, pretty=args.pretty)
        return EXIT_BADARGS

    except KmsError as e:
        write_json({"error": str(e), "code": getattr(e, "code", "KMS_ERROR")}, pretty=args.pretty)
        return EXIT_RUNTIME
    except Exception as e:  # noqa: BLE001
        LOG.exception("Ошибка KMS")
        write_json({"error": str(e)}, pretty=args.pretty)
        return EXIT_RUNTIME


# =========================
# Подкоманда: pki (CRL)
# =========================

def cmd_pki_crl_check(args: argparse.Namespace) -> int:
    try:
        cert_pem = open(args.cert, "rb").read()
        issuer_pem = open(args.issuer, "rb").read()
        from cryptography import x509
        cert = x509.load_pem_x509_certificate(cert_pem)
        issuer = x509.load_pem_x509_certificate(issuer_pem)

        mgr = CRLManager(CRLConfig(
            fetch_timeout=args.timeout,
            verify_tls=not args.insecure,
            cache_dir=args.cache_dir,
        ))
        info = mgr.check_certificate_revocation(certificate=cert, issuer_certificate=issuer)
        write_json(
            {
                "revoked": info.revoked,
                "reason": info.reason,
                "revocation_date": format_rfc3339(info.revocation_date) if info.revocation_date else None,
                "invalidity_date": format_rfc3339(info.invalidity_date) if info.invalidity_date else None,
                "source": info.source,
            },
            pretty=args.pretty,
        )
        return EXIT_OK if not info.revoked else EXIT_RUNTIME
    except FileNotFoundError as e:
        write_json({"error": f"file not found: {e.filename}"}, pretty=args.pretty)
        return EXIT_NOTFOUND
    except CRLError as e:
        write_json({"error": str(e), "code": getattr(e, "code", "CRL_ERROR")}, pretty=args.pretty)
        return EXIT_RUNTIME
    except Exception as e:  # noqa: BLE001
        LOG.exception("Ошибка проверки CRL")
        write_json({"error": str(e)}, pretty=args.pretty)
        return EXIT_RUNTIME


# =========================
# Подкоманда: td (threat detection)
# =========================

def _build_engine(defaults: Optional[Mapping[str, Any]] = None) -> DetectorEngine:
    engine = DetectorEngine()
    engine.register(brute_force_factory, config=(defaults or {}).get("brute_force", {}))
    engine.register(impossible_travel_factory, config=(defaults or {}).get("impossible_travel", {}))
    engine.register(rare_country_factory, config=(defaults or {}).get("rare_country", {}))
    engine.register(token_replay_factory, config=(defaults or {}).get("token_replay", {}))
    engine.register(suspicious_nomfa_factory, config=(defaults or {}).get("suspicious_nomfa", {}))
    engine.register(priv_esc_factory, config=(defaults or {}).get("priv_esc", {}))
    engine.register(anomalous_download_factory, config=(defaults or {}).get("anomalous_download", {}))
    return engine


def cmd_td_run(args: argparse.Namespace) -> int:
    """
    Читает события из stdin/файла (JSON массив или NDJSON) и выводит Findings в NDJSON.
    """
    cfg = read_structured(args.config) if args.config else {}
    engine = _build_engine(cfg or {})

    data = read_structured(args.input)
    events: List[Mapping[str, Any]] = []
    if isinstance(data, list):
        events = data
    elif isinstance(data, dict):
        events = [data]
    else:
        LOG.error("Ожидались JSON/NDJSON события")
        return EXIT_BADARGS

    findings: List[Mapping[str, Any]] = []
    for ev in events:
        try:
            se = SecurityEvent(**ev)
            out = engine.handle(se)
            for f in out:
                findings.append(json.loads(f.json()))
        except Exception as e:  # noqa: BLE001
            if args.skip_bad:
                LOG.warning("Пропуск испорченного события: %s", e)
                continue
            raise

    write_json(findings, ndjson=True)
    return EXIT_OK


# =========================
# Подкоманда: time (утилиты)
# =========================

def cmd_time_util(args: argparse.Namespace) -> int:
    if args.op == "now":
        write_json({"now": format_rfc3339(now_utc())}, pretty=args.pretty)
        return EXIT_OK
    if args.op == "parse":
        dt = parse_rfc3339(args.value)
        write_json({"epoch_ms": epoch_milliseconds(), "parsed": format_rfc3339(dt)}, pretty=args.pretty)
        return EXIT_OK
    if args.op == "duration-parse":
        td = parse_duration(args.value)
        write_json({"seconds": td.total_seconds(), "short": format_duration(td, short=True, ms=True)}, pretty=args.pretty)
        return EXIT_OK
    if args.op == "window":
        size = parse_duration(args.size) if not args.size.isdigit() else timedelta(seconds=int(args.size))
        end = parse_rfc3339(args.end) if args.end else now_utc()
        start, end2 = window_bounds(end=end, size=size)
        write_json({"start": format_rfc3339(start), "end": format_rfc3339(end2)}, pretty=args.pretty)
        return EXIT_OK
    write_json({"error": "unsupported time op"}, pretty=args.pretty)
    return EXIT_BADARGS


# =========================
# Аргументы командной строки
# =========================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="security-core",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(
            """\
            Security Core CLI
            Примеры:
              # Оценка авторизации
              security-core authz evaluate --tenant acme --policies policies.json --request req.json --explain

              # Управление группами с файлом-снапшотом
              security-core iam groups --tenant acme --snapshot groups.json create --group-id analysts --roles role.read

              # Конвертное шифрование через GCP KMS
              cat secret.bin | security-core kms encrypt --key projects/P/locations/L/keyRings/R/cryptoKeys/K > env.json
              cat env.json | security-core kms decrypt --aad '{"tenant":"acme"}' > plain.bin

              # Проверка CRL
              security-core pki crl check --cert end.pem --issuer ca.pem

              # Детекция угроз (NDJSON → NDJSON)
              cat events.ndjson | security-core td run > findings.ndjson

              # Время
              security-core time now
            """
        ),
    )
    p.add_argument("--log-level", default=os.getenv("SECURITY_CORE_LOG", "INFO"), help="DEBUG|INFO|WARN|ERROR")
    p.add_argument("--pretty", action="store_true", help="Печать JSON с отступами")

    sub = p.add_subparsers(dest="cmd", required=True)

    # authz
    pa = sub.add_parser("authz", help="Авторизация (PDP)")
    spa = pa.add_subparsers(dest="sub", required=True)
    pae = spa.add_parser("evaluate", help="Оценить запрос")
    pae.add_argument("--tenant", required=True, help="Идентификатор арендатора")
    pae.add_argument("--policies", nargs="+", help="Файлы политик (JSON/NDJSON/YAML)")
    pae.add_argument("--policies-names", nargs="*", help="Ограничить списком имен политик")
    pae.add_argument("--request", required=True, help="JSON запрос (файл или '-')")
    pae.add_argument("--explain", action="store_true", help="Включить объяснение")
    pae.set_defaults(func=cmd_authz_evaluate)

    # iam groups
    pi = sub.add_parser("iam", help="IAM операции")
    spi = pi.add_subparsers(dest="sub", required=True)
    pig = spi.add_parser("groups", help="Управление группами (через снапшот)")
    pig.add_argument("--tenant", required=True)
    pig.add_argument("--snapshot", help="Путь к snapshot JSON")
    pgsub = pig.add_subparsers(dest="op", required=True)
    pgl = pgsub.add_parser("list"); pgl.add_argument("--prefix"); pgl.add_argument("--limit", type=int, default=100); pgl.set_defaults(func=cmd_iam_groups)
    pgc = pgsub.add_parser("create"); pgc.add_argument("--group-id", required=True); pgc.add_argument("--display-name"); pgc.add_argument("--description"); pgc.add_argument("--labels"); pgc.add_argument("--attributes"); pgc.add_argument("--roles", nargs="*"); pgc.add_argument("--members", help="JSON/NDJSON со списком MemberRef"); pgc.add_argument("--force", action="store_true"); pgc.set_defaults(func=cmd_iam_groups)
    pgd = pgsub.add_parser("delete"); pgd.add_argument("--group-id", required=True); pgd.add_argument("--force", action="store_true"); pgd.set_defaults(func=cmd_iam_groups)
    pgm = pgsub.add_parser("members"); pgm.add_argument("--group-id", required=True); pgm.add_argument("--add"); pgm.add_argument("--remove"); pgm.add_argument("--force", action="store_true"); pgm.set_defaults(func=cmd_iam_groups)

    # kms
    pk = sub.add_parser("kms", help="KMS операции (GCP)")
    spk = pk.add_subparsers(dest="op", required=True)
    pk.add_argument("--default-key", help="project/location/ring/key (по умолчанию)")
    pk.add_argument("--timeout", type=float, default=10.0)
    pk.add_argument("--max-attempts", type=int, default=5)
    pke = spk.add_parser("encrypt"); pke.add_argument("--key", help="Key resource"); pke.add_argument("--aad", help="JSON AAD"); pke.add_argument("--input", help="Файл или '-'"); pke.set_defaults(func=cmd_kms)
    pkd = spk.add_parser("decrypt"); pkd.add_argument("--aad", help="JSON AAD"); pkd.add_argument("--input", help="Файл или '-'"); pkd.set_defaults(func=cmd_kms)
    pks = spk.add_parser("sign"); pks.add_argument("--key-version", required=True, help=".../cryptoKeyVersions/N или короткая форма"); pks.add_argument("--hash-alg", default="SHA256"); pks.add_argument("--input", help="Файл или '-'"); pks.set_defaults(func=cmd_kms)
    pkv = spk.add_parser("verify"); pkv.add_argument("--key-version", required=True); pkv.add_argument("--hash-alg", default="SHA256"); pkv.add_argument("--input", help="Данные"); pkv.add_argument("--signature", help="Подпись"); pkv.set_defaults(func=cmd_kms)

    # pki crl
    pp = sub.add_parser("pki", help="PKI операции")
    spp = pp.add_subparsers(dest="sub", required=True)
    pcrl = spp.add_parser("crl", help="CRL проверка")
    spcrl = pcrl.add_subparsers(dest="op", required=True)
    pcrlc = spcrl.add_parser("check", help="Проверить отзыв сертификата по CRL")
    pcrlc.add_argument("--cert", required=True, help="Путь к проверяемому сертификату (PEM)")
    pcrlc.add_argument("--issuer", required=True, help="Путь к сертификату издателя (PEM)")
    pcrlc.add_argument("--timeout", type=float, default=7.5)
    pcrlc.add_argument("--insecure", action="store_true", help="Отключить проверку TLS")
    pcrlc.add_argument("--cache-dir", help="Каталог файлового кэша CRL")
    pcrlc.set_defaults(func=cmd_pki_crl_check)

    # threat detection
    td = sub.add_parser("td", help="Детекция угроз")
    std = td.add_subparsers(dest="sub", required=True)
    tdr = std.add_parser("run", help="Обработать события и вывести findings (NDJSON)")
    tdr.add_argument("--input", help="Файл JSON/NDJSON или '-' (stdin)", default="-")
    tdr.add_argument("--config", help="Конфиг детекторов (JSON/YAML)")
    tdr.add_argument("--skip-bad", action="store_true", help="Пропускать испорченные события")
    tdr.set_defaults(func=cmd_td_run)

    # time
    tm = sub.add_parser("time", help="Временные утилиты")
    stm = tm.add_subparsers(dest="op", required=True)
    tnow = stm.add_parser("now"); tnow.set_defaults(func=cmd_time_util)
    tparse = stm.add_parser("parse"); tparse.add_argument("value"); tparse.set_defaults(func=cmd_time_util)
    tdur = stm.add_parser("duration-parse"); tdur.add_argument("value"); tdur.set_defaults(func=cmd_time_util)
    twin = stm.add_parser("window"); twin.add_argument("--size", required=True); twin.add_argument("--end"); twin.set_defaults(func=cmd_time_util)

    return p


# =========================
# main
# =========================

def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(args.log_level)
    try:
        if not hasattr(args, "func"):
            parser.print_help()
            return EXIT_BADARGS
        return int(args.func(args))
    except json.JSONDecodeError as e:
        LOG.error("Ошибка JSON: %s", e)
        return EXIT_BADARGS
    except KeyboardInterrupt:
        LOG.warning("Прервано пользователем")
        return EXIT_RUNTIME
    except Exception as e:  # noqa: BLE001
        LOG.exception("Неперехваченное исключение")
        write_json({"error": str(e)}, pretty=getattr(args, "pretty", False))
        return EXIT_RUNTIME


if __name__ == "__main__":
    sys.exit(main())
