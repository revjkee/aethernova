from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import json
import logging
import os
import signal
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

# Опциональные зависимости
try:
    import yaml  # PyYAML
    _YAML_OK = True
except Exception:
    _YAML_OK = False

try:
    from croniter import croniter  # для окон обслуживания
    _CRON_OK = True
except Exception:
    _CRON_OK = False

# Опциональные клиенты
try:
    import requests  # для Elasticsearch/Kafka REST брокеров
    _REQ_OK = True
except Exception:
    _REQ_OK = False

try:
    import boto3  # для S3 lifecycle
    _BOTO_OK = True
except Exception:
    _BOTO_OK = False

try:
    import psycopg  # psycopg3
    _PSYCOPG_OK = True
except Exception:
    _PSYCOPG_OK = False

try:
    from opentelemetry import trace
    _TRACER = trace.get_tracer(__name__)
except Exception:
    _TRACER = None

log = logging.getLogger("oblivionvault.retention.scheduler")


# =========================
# Конфигурация рантайма
# =========================

@dataclass
class RuntimeConfig:
    policy_path: str
    environment: str = os.getenv("OV_ENV", "prod")
    mode: str = "plan"  # plan|apply
    out_dir: str = os.getenv("OV_RETENTION_OUT", "./out")
    plan_file: str = ""  # если пусто — создаётся в out_dir
    lock_file: str = os.getenv("OV_RETENTION_LOCKFILE", "/tmp/ov-retention.lock")
    tz: str = os.getenv("OV_TZ", "Europe/Stockholm")
    # Прямое применение экзекьюторов (опасно в прод без CI/CD)
    direct_apply: bool = os.getenv("OV_RETENTION_DIRECT_APPLY", "false").lower() == "true"
    # PostgreSQL Jobs
    pg_dsn: Optional[str] = os.getenv("OV_PG_DSN") or None
    # Approvals через переменную окружения (CSV имён/идентификаторов)
    approvals_env: str = os.getenv("OV_RETENTION_APPROVALS", "")
    # Лимит параллельных задач применения (для direct_apply)
    max_concurrent: int = int(os.getenv("OV_RETENTION_MAX_CONCURRENCY", "4"))
    # Секунд до принудительного завершения
    shutdown_grace: int = int(os.getenv("OV_RETENTION_SHUTDOWN_GRACE_SEC", "15"))


# =========================
# Модель действий
# =========================

@dataclass
class Action:
    system: str                 # s3|elasticsearch|kafka|loki|prometheus|tempo|clickhouse|postgresql|redis
    name: str                   # человекочитаемое имя
    env: str                    # target environment
    params: Dict[str, Any]      # нормализованные параметры для экзекьютора
    dry_run: bool               # dry-run флаг
    estimate_delete_bytes: Optional[int] = None
    risk_level: str = "low"     # low|medium|high
    reason: str = "policy"
    approval_required: int = 0  # мин. число апрувов
    idempotent_key: str = ""    # ключ идемпотентности
    origin: Dict[str, Any] = field(default_factory=dict)  # ссылка на исходное правило/генератор


# =========================
# Утилиты времени/cron/локов
# =========================

class FileLock:
    def __init__(self, path: str):
        self.path = path
        self._fh = None

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.release()

    def acquire(self, timeout: int = 0):
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self.path, "w")
        if os.name == "posix":
            import fcntl
            start = time.time()
            while True:
                try:
                    fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    self._fh.write(str(os.getpid()))
                    self._fh.flush()
                    return
                except BlockingIOError:
                    if timeout and time.time() - start > timeout:
                        raise TimeoutError("lock timeout")
                    time.sleep(0.1)
        else:
            if Path(self.path).exists():
                raise TimeoutError("lock exist")
            self._fh.write(str(os.getpid()))
            self._fh.flush()

    def release(self):
        if self._fh:
            try:
                if os.name == "posix":
                    import fcntl
                    fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
            finally:
                self._fh.close()
                with contextlib.suppress(Exception):
                    Path(self.path).unlink(missing_ok=True)


def in_maintenance_window(spec: Mapping[str, Any], now: Optional[dt.datetime] = None) -> bool:
    windows = (spec or {}).get("schedules", {}).get("applyWindow", {}).get("maintenanceWindows", []) or \
              (spec or {}).get("schedules", {}).get("maintenanceWindows", [])  # DSL подсхема
    if not windows:
        return True
    now = now or dt.datetime.now(dt.timezone.utc)
    if not _CRON_OK:
        log.warning("croniter not installed; maintenance windows cannot be evaluated. Assuming allowed.")
        return True
    # Разрешаем, если сейчас попадает в любой cron-слот +-60 сек
    for w in windows:
        cron = w.get("cron") or w.get("CRON") or ""
        try:
            itr = croniter(cron, now - dt.timedelta(seconds=60))
            prev = itr.get_prev(datetime=True)
            next_ = croniter(cron, prev).get_next(datetime=True)
            if prev <= now <= next_:
                return True
        except Exception:
            log.warning("invalid cron '%s' in maintenance window", cron)
    return False


# =========================
# Загрузка и нормализация политик
# =========================

def load_yaml(path: str) -> Dict[str, Any]:
    if not _YAML_OK:
        raise RuntimeError("PyYAML is required to load policies")
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("policy must be a YAML mapping at top-level")
    return data


def eval_safeguards(policy: Mapping[str, Any], env: str, approvals: List[str]) -> Tuple[bool, str]:
    # enabled/dryRun/legalHold из bundle или DSL
    flags = {}
    if "spec" in policy and isinstance(policy["spec"], dict):
        flags["enabled"] = policy["spec"].get("enabled", True)
        flags["dryRun"] = policy["spec"].get("dryRun", False)
    if "globals" in policy and isinstance(policy["globals"], dict):
        g = policy["globals"]
        flags["enabled"] = g.get("flags", {}).get("enabled", flags.get("enabled", True))
        flags["dryRun"] = g.get("flags", {}).get("dryRun", flags.get("dryRun", False))

    legal_hold = False
    # legal hold в bundle defaults
    if "spec" in policy:
        legal = policy["spec"].get("defaults", {}).get("legalHold", {}).get("enabled")
        # активный признак передается из внешнего контура; для простоты рассматриваем env-переменную
    legal_hold_active = os.getenv("OV_LEGAL_HOLD", "false").lower() == "true"

    if not flags.get("enabled", True):
        return False, "guard:engine_disabled"
    if env == "prod" and flags.get("dryRun", False):
        return False, "guard:dry_run_in_prod"
    if legal_hold and legal_hold_active:
        return False, "guard:legal_hold_active"

    # approvals по окружению
    min_approvals = 0
    # из bundle
    if "spec" in policy and "safeguards" in policy["spec"]:
        req = policy["spec"]["safeguards"].get("requireApprovals", {}).get(env)
        if isinstance(req, dict):
            min_approvals = int(req.get("minApprovals", 0))
    # из DSL
    if "globals" in policy and "approval" in policy["globals"]:
        # на уровне DSL глобальный минимум, а в environments — override
        min_approvals = max(min_approvals, int(policy["globals"]["approval"].get("minApprovals", 0)))
        for e in policy.get("environments", []):
            if e.get("name") == env:
                ov = e.get("overrides", {}).get("approval", {})
                if "minApprovals" in ov:
                    min_approvals = int(ov["minApprovals"])
                break

    if len(approvals) < min_approvals:
        return False, f"guard:approvals_required:{min_approvals}"
    return True, "ok"


def compile_actions(policy: Mapping[str, Any], env: str, dry_run: bool) -> List[Action]:
    """
    Поддержка двух схем:
      1) RetentionPolicyBundle (прямое перечисление systems + bindings)
      2) RetentionPolicyDSL (policySets/rules/bindings + generators)
    На выходе — нормализованные Actions для экзекьюторов систем.
    """
    kind = (policy.get("kind") or "").lower()
    actions: List[Action] = []
    if kind == "retentionpolicybundle".lower():
        actions.extend(_compile_from_bundle(policy, env, dry_run))
    elif kind == "retentionpolicydsl".lower():
        actions.extend(_compile_from_dsl(policy, env, dry_run))
    else:
        raise ValueError(f"unsupported policy kind: {policy.get('kind')}")

    return actions


def _compile_from_bundle(bundle: Mapping[str, Any], env: str, dry_run: bool) -> List[Action]:
    acts: List[Action] = []
    bindings = bundle.get("bindings", [])
    systems_spec = bundle.get("spec", {}).get("systems", {})
    for b in bindings:
        if b.get("environment") != env:
            continue
        targets = b.get("targets", [])
        for t in targets:
            system = t.get("system")
            spec = t.get("spec") or systems_spec.get(system) or {}
            name = f"{system}-apply"
            acts.append(Action(
                system=system,
                name=name,
                env=env,
                params={"spec": spec},
                dry_run=dry_run,
                risk_level=_estimate_risk(system, spec),
                approval_required=0,
                idempotent_key=f"{env}:{system}:{hash(json.dumps(spec, sort_keys=True))}",
                origin={"binding": b.get("name", ""), "system": system},
            ))
    return acts


_KIND_TO_SYSTEM = {
    "loki.stream": "loki",
    "prometheus.metrics": "prometheus",
    "tempo.traces": "tempo",
    "elasticsearch.index": "elasticsearch",
    "clickhouse.table": "clickhouse",
    "postgres.table": "postgresql",
    "s3.bucket": "s3",
    "kafka.topic": "kafka",
}

def _compile_from_dsl(dsl: Mapping[str, Any], env: str, dry_run: bool) -> List[Action]:
    acts: List[Action] = []
    # Простая реализация: разворачиваем bindings -> policySets/rules -> action
    policy_sets = {ps["name"]: ps for ps in dsl.get("policySets", []) if "name" in ps}
    rules_index = {r["name"]: r for r in dsl.get("rules", []) if "name" in r}
    generators = dsl.get("generators", {})

    def render_target(rule: Mapping[str, Any], override_action: Optional[Mapping[str, Any]] = None) -> Optional[Action]:
        tgt = rule.get("target", {})
        kind = tgt.get("kind")
        system = _KIND_TO_SYSTEM.get(kind)
        if not system:
            return None
        action_body = rule.get("action", {})
        if override_action:
            # поверх перезаписываем
            action_body = _merge_dicts(action_body, override_action)
        # Маппинг через generators: переносим поля action_body в system params
        params = _map_via_generators(generators, system, action_body)
        name = f"{system}-{rule.get('name', 'rule')}"
        return Action(
            system=system,
            name=name,
            env=env,
            params=params,
            dry_run=dry_run,
            risk_level=_estimate_risk(system, params),
            approval_required=0,
            idempotent_key=f"{env}:{system}:{hash(json.dumps(params, sort_keys=True))}",
            origin={"rule": rule.get("name"), "kind": kind},
        )

    for b in dsl.get("bindings", []):
        # отбор по окружению
        if b.get("environment") != env:
            continue
        # базовые элементы
        for ps_name in b.get("apply", []):
            if isinstance(ps_name, dict) and "policySet" in ps_name:
                ps_name = ps_name["policySet"]
            ps = policy_sets.get(ps_name)
            if not ps:
                continue
            for r in ps.get("rules", []):
                a = render_target(r)
                if a:
                    acts.append(a)
        # одиночные правила
        for rname in b.get("apply", []):
            # уже разобрались policySet; здесь ловим случаи "rule: ..."
            pass
        for entry in b.get("apply", []):
            if isinstance(entry, dict) and "rule" in entry:
                r = rules_index.get(entry["rule"])
                if r:
                    a = render_target(r)
                    if a:
                        acts.append(a)
        # overrides
        for ov in b.get("overrides", []):
            r = None
            if "target" in ov:
                # экспериментальная поддержка: создаем synthetic rule с action из override
                target = ov["target"]
                kind = target.get("kind")
                if not kind:
                    continue
                system = _KIND_TO_SYSTEM.get(kind)
                if not system:
                    continue
                action_body = ov.get("action", {})
                params = _map_via_generators(generators, system, action_body)
                a = Action(
                    system=system,
                    name=f"{system}-override",
                    env=env,
                    params=params,
                    dry_run=dry_run,
                    risk_level=_estimate_risk(system, params),
                    approval_required=0,
                    idempotent_key=f"{env}:{system}:{hash(json.dumps(params, sort_keys=True))}",
                    origin={"override": True, "kind": kind},
                )
                acts.append(a)

    return acts


def _map_via_generators(generators: Mapping[str, Any], system: str, action_body: Mapping[str, Any]) -> Dict[str, Any]:
    # generators.<system>.map содержит перенос ключей из action_body в params
    gen = generators.get(system, {}) if isinstance(generators, dict) else {}
    mapping = gen.get("map", {}) if isinstance(gen, dict) else {}
    params: Dict[str, Any] = {}
    if not mapping:
        # fallback: положим как есть
        params.update(action_body)
        return params

    # Простая адресация по верхнему уровню
    for target_key, src_path in mapping.items():
        val = _get_in(action_body, _path=src_path)
        if val is not None:
            params[target_key] = val
    # сохраняем исходные action значения для прозрачности
    params["_raw_action"] = action_body
    return params


def _get_in(d: Mapping[str, Any], _path: str):
    # путь формата ".a.b.c"
    if not _path or not isinstance(d, dict):
        return None
    cur = d
    for part in _path.strip(".").split("."):
        if not isinstance(cur, dict):
            return None
        if part not in cur:
            return None
        cur = cur[part]
    return cur


def _merge_dicts(a: Mapping[str, Any], b: Mapping[str, Any]) -> Dict[str, Any]:
    out = dict(a)
    for k, v in (b or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge_dicts(out[k], v)  # type: ignore
        else:
            out[k] = v
    return out


def _estimate_risk(system: str, params: Mapping[str, Any]) -> str:
    # Примитивная эвристика: длинные TTL / delete-фазы = выше риск
    if system in ("elasticsearch", "s3", "clickhouse"):
        return "medium"
    if system in ("postgresql", "kafka"):
        return "high" if "retention" in params and params["retention"].get("time") in ("-1", None) else "medium"
    return "low"


# =========================
# Экзекьюторы систем (plug-in)
# =========================

class Executor:
    system: str
    def plan(self, action: Action) -> Dict[str, Any]:
        raise NotImplementedError
    def apply(self, action: Action) -> Dict[str, Any]:
        # По умолчанию не реализовано; планировщик может записать артефакты для GitOps
        raise NotImplementedError


class ElasticsearchExecutor(Executor):
    system = "elasticsearch"
    def __init__(self):
        self.endpoint = os.getenv("OV_ES_ENDPOINT")
        self.user = os.getenv("OV_ES_USER")
        self.password = os.getenv("OV_ES_PASSWORD")

    def plan(self, action: Action) -> Dict[str, Any]:
        ilm = action.params.get("ilm") or action.params.get("elasticsearch", {}).get("ilm")
        return {"type": "es_ilm_put", "endpoint": self.endpoint, "policy": ilm}

    def apply(self, action: Action) -> Dict[str, Any]:
        if not _REQ_OK:
            raise RuntimeError("requests not installed")
        if not self.endpoint:
            raise RuntimeError("OV_ES_ENDPOINT is required")
        body = {"policy": action.params.get("ilm")}
        name = (action.params.get("_raw_action", {}).get("name") or "default-logs").replace("/", "_")
        url = f"{self.endpoint}/_ilm/policy/{name}"
        resp = requests.put(url, json=body, auth=(self.user, self.password) if self.user else None, timeout=10)
        if resp.status_code >= 300:
            raise RuntimeError(f"ES ILM PUT failed: {resp.status_code} {resp.text}")
        return {"applied": True, "policy": name}


class S3Executor(Executor):
    system = "s3"
    def __init__(self):
        self.profile = os.getenv("AWS_PROFILE")
        self.region = os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION")

    def plan(self, action: Action) -> Dict[str, Any]:
        return {"type": "s3_lifecycle_put", "lifecycle": action.params.get("lifecycle"), "encryption": action.params.get("encryption")}

    def apply(self, action: Action) -> Dict[str, Any]:
        if not _BOTO_OK:
            raise RuntimeError("boto3 not installed")
        session = boto3.Session(profile_name=self.profile, region_name=self.region) if self.profile else boto3.Session(region_name=self.region)
        s3 = session.client("s3")
        bucket = action.params.get("_raw_action", {}).get("bucket") or action.params.get("bucket") or action.params.get("name")
        if not bucket:
            raise RuntimeError("missing bucket name in action")
        # Lifecycle
        lc_rules = action.params.get("lifecycle")
        if lc_rules:
            cfg = {"Rules": _to_s3_rules(lc_rules)}
            s3.put_bucket_lifecycle_configuration(Bucket=bucket, LifecycleConfiguration=cfg)
        # SSE-KMS
        if action.params.get("encryption", {}).get("kmsKeyAlias"):
            sse = {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms", "KMSMasterKeyID": action.params["encryption"]["kmsKeyAlias"]}}]}
            s3.put_bucket_encryption(Bucket=bucket, ServerSideEncryptionConfiguration=sse)
        return {"applied": True, "bucket": bucket}


def _to_s3_rules(rules: Iterable[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for r in rules:
        rule = {"ID": r.get("id", f"rule-{len(out)+1}"), "Status": "Enabled"}
        flt = r.get("filter") or {}
        if "prefix" in flt:
            rule["Filter"] = {"Prefix": flt["prefix"]}
        if r.get("expiration"):
            rule["Expiration"] = {"Days": int(r["expiration"]["days"])}
        if r.get("transitions"):
            ts = []
            for t in r["transitions"]:
                ts.append({"Days": int(t["days"]), "StorageClass": t["storageClass"]})
            rule["Transitions"] = ts
        out.append(rule)
    return out


class KafkaExecutor(Executor):
    system = "kafka"
    def __init__(self):
        self.rest = os.getenv("OV_KAFKA_REST")  # e.g. http://kafka-rest:8082
    def plan(self, action: Action) -> Dict[str, Any]:
        return {"type": "kafka_retention", "retention": action.params.get("retention")}
    def apply(self, action: Action) -> Dict[str, Any]:
        if not _REQ_OK:
            raise RuntimeError("requests not installed")
        if not self.rest:
            raise RuntimeError("OV_KAFKA_REST is required")
        # Демонстрационно: PATCH topic configs
        topic = action.params.get("_raw_action", {}).get("topic") or action.params.get("topic") or "unknown"
        cfg = {}
        ret = action.params.get("retention") or {}
        if "time" in ret:
            cfg["retention.ms"] = _duration_to_ms(ret["time"])
        if "size" in ret and str(ret["size"]).lower() not in ("-1", "none"):
            cfg["retention.bytes"] = _size_to_bytes(ret["size"])
        url = f"{self.rest}/v3/clusters/xxx/topics/{topic}/configs:alter"  # placeholder
        # Для безопасности возвращаем план; прямое применение потребует конкретного REST API
        return {"applied": False, "reason": "kafka direct apply is disabled by default", "topic": topic, "config": cfg}


EXECUTORS: Dict[str, Executor] = {
    "elasticsearch": ElasticsearchExecutor(),
    "s3": S3Executor(),
    "kafka": KafkaExecutor(),
    # Остальные системы по умолчанию только планируют через артефакты для GitOps
}


# =========================
# Применение через очередь задач (PostgreSQL)
# =========================

def enqueue_job(pg_dsn: str, queue: str, kind: str, payload: Dict[str, Any], dedup_key: str) -> Optional[str]:
    if not _PSYCOPG_OK:
        log.warning("psycopg not installed; cannot enqueue job")
        return None
    with psycopg.connect(pg_dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT ov_jobs.enqueue_job(%s,%s,%s,%s)",
                (queue, kind, json.dumps(payload), json.dumps({"dedup_key": dedup_key}))
            )
            return cur.fetchone()[0]


# =========================
# Основная логика планировщика
# =========================

def plan_and_optionally_apply(rt: RuntimeConfig) -> int:
    policy = load_yaml(rt.policy_path)

    approvals = [x.strip() for x in (rt.approvals_env or "").split(",") if x.strip()]
    allowed, reason = eval_safeguards(policy, rt.environment, approvals)
    if not allowed:
        log.error("Safeguard deny: %s", reason)
        _emit_audit(rt, "deny", {"reason": reason})
        return 2

    if not in_maintenance_window(policy):
        log.info("Not in maintenance window; exiting")
        _emit_audit(rt, "skip_window", {})
        return 0

    dry_run = True if rt.mode == "plan" else False
    actions = compile_actions(policy, rt.environment, dry_run=dry_run)

    # Backpressure hooks (заглушка, сюда подключаются реальные проверки)
    if _backpressure_triggered(policy):
        log.warning("Backpressure triggered; skipping apply")
        _emit_audit(rt, "skip_backpressure", {})
        return 3

    out_dir = Path(rt.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    plan_path = Path(rt.plan_file) if rt.plan_file else out_dir / f"retention_plan_{rt.environment}_{int(time.time())}.jsonl"

    count = 0
    with plan_path.open("w", encoding="utf-8") as f:
        for a in actions:
            plan_record = {
                "env": a.env,
                "system": a.system,
                "name": a.name,
                "dry_run": a.dry_run,
                "risk": a.risk_level,
                "params": a.params,
                "idempotent_key": a.idempotent_key,
                "origin": a.origin,
            }
            # план от экзекьютора
            execu = EXECUTORS.get(a.system)
            if execu:
                with _span("plan", a):
                    try:
                        plan_record["executor_plan"] = execu.plan(a)
                    except Exception as e:
                        plan_record["executor_plan_error"] = str(e)
            f.write(json.dumps(plan_record, ensure_ascii=False) + "\n")
            count += 1

    log.info("Plan written: %s (%d actions)", plan_path, count)
    _emit_audit(rt, "plan_ok", {"file": str(plan_path), "count": count})

    if rt.mode != "apply":
        return 0

    # APPLY: либо прямая запись в ov_jobs, либо direct_apply
    applied = 0
    for a in actions:
        if rt.pg_dsn:
            job_id = enqueue_job(rt.pg_dsn, "retention", f"{a.system}.apply", {"action": _action_to_payload(a)}, a.idempotent_key)
            log.info("Enqueued job %s for %s", job_id, a.name)
            applied += 1
            continue

        if rt.direct_apply:
            execu = EXECUTORS.get(a.system)
            if not execu:
                log.info("No direct executor for %s; skipping", a.system)
                continue
            with _span("apply", a):
                try:
                    res = execu.apply(a)
                    log.info("Applied %s: %s", a.name, _short(res))
                    applied += 1
                except Exception as e:
                    log.error("Apply failed for %s: %s", a.name, e)
        else:
            log.info("Direct apply disabled; skipping %s", a.name)

    _emit_audit(rt, "apply_done", {"applied": applied, "total": len(actions)})
    return 0


def _action_to_payload(a: Action) -> Dict[str, Any]:
    return {
        "system": a.system,
        "env": a.env,
        "name": a.name,
        "params": a.params,
        "risk": a.risk_level,
        "idempotent_key": a.idempotent_key,
        "origin": a.origin,
    }


def _short(obj: Any, n: int = 300) -> str:
    s = json.dumps(obj, ensure_ascii=False)
    return s if len(s) <= n else s[:n] + "...(+)"


def _emit_audit(rt: RuntimeConfig, event: str, payload: Dict[str, Any]):
    record = {"ts": dt.datetime.now(dt.timezone.utc).isoformat(), "event": event, "env": rt.environment, **payload}
    log.info("audit %s", json.dumps(record, ensure_ascii=False))


def _duration_to_ms(s: str) -> int:
    # "14d" -> ms
    units = {"ms": 1, "s": 1000, "m": 60_000, "h": 3_600_000, "d": 86_400_000}
    s = s.strip().lower()
    for u, mul in units.items():
        if s.endswith(u):
            return int(s[:-len(u)]) * mul
    return int(s)


def _size_to_bytes(s: str) -> int:
    s = str(s).strip().lower()
    units = {"ki": 1024, "mi": 1024**2, "gi": 1024**3, "ti": 1024**4}
    for u, mul in units.items():
        if s.endswith(u):
            return int(s[:-len(u)]) * mul
    if s.endswith("b"):
        return int(s[:-1])
    return int(s)


def _backpressure_triggered(policy: Mapping[str, Any]) -> bool:
    # Читаем лимиты очереди из policy.schedules.backpressure, но без реальных метрик — заглушка
    bp = policy.get("spec", {}).get("schedules", {}).get("backpressure") or policy.get("schedules", {}).get("backpressure")
    if not bp:
        return False
    # место для интеграции с реальными счетчиками (очереди, cpu, io)
    return False


# =========================
# CLI и запуск
# =========================

def _setup_logging():
    level = os.getenv("OV_LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

def _span(name: str, action: Action):
    if not _TRACER:
        return contextlib.nullcontext()
    return _TRACER.start_as_current_span(f"retention.{name}", attributes={
        "system": action.system,
        "env": action.env,
        "name": action.name,
        "risk": action.risk_level,
    })

def main(argv: Optional[List[str]] = None) -> int:
    _setup_logging()
    p = argparse.ArgumentParser(description="OblivionVault Retention Scheduler")
    p.add_argument("--policy", required=True, help="Path to retention policy YAML (Bundle or DSL)")
    p.add_argument("--env", default=os.getenv("OV_ENV", "prod"), help="Environment name (prod/staging/dev)")
    p.add_argument("--mode", choices=["plan", "apply"], default="plan")
    p.add_argument("--out", default=os.getenv("OV_RETENTION_OUT", "./out"))
    p.add_argument("--plan-file", default="")
    p.add_argument("--lock", default=os.getenv("OV_RETENTION_LOCKFILE", "/tmp/ov-retention.lock"))
    args = p.parse_args(argv)

    rt = RuntimeConfig(
        policy_path=args.policy,
        environment=args.env,
        mode=args.mode,
        out_dir=args.out,
        plan_file=args.plan_file,
        lock_file=args.lock,
    )

    with FileLock(rt.lock_file):
        # Плавное завершение
        stop = threading.Event()
        def handle_sig(*_):
            stop.set()
        with contextlib.suppress(Exception):
            signal.signal(signal.SIGINT, handle_sig)
            signal.signal(signal.SIGTERM, handle_sig)
        rc = plan_and_optionally_apply(rt)
        return rc

if __name__ == "__main__":
    sys.exit(main())
