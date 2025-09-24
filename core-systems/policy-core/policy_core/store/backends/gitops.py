# policy-core/policy_core/store/backends/gitops.py
# -*- coding: utf-8 -*-
"""
GitOps Policy Store Backend (Async)

Возможности:
- Клонирование/обновление Git (HTTPS/SSH/Token), shallow/branch pin, subdir scoping
- Денормализация политик в атомарный снапшот с версионностью (rev, ts)
- Схемная валидация (Pydantic) для правил LocalRuleEngine
- Многоарендность (policies/<tenant>/**)
- Опциональная проверка GPG-подписей commit/tag и/или *.asc рядом с файлами
- Экспоненциальный backoff, лимит частоты (rate-limit) и ручной триггер refresh()
- Откат к последней валидной ревизии при ошибке (last_good.json)
- Прометрики (Prometheus) и OpenTelemetry-трейсинг
- Структурные JSON-логи (без утечек секретов)
- Потокобезопасный доступ; подписки на обновления (observer pattern)

Зависимости (опционально подключаемые):
    pip install GitPython pydantic prometheus-client opentelemetry-sdk python-gnupg

Формат файлов политик (yaml/json), пример:
  - effect: allow
    match:
      rpc.method: HealthCheck
      resource.type: health
    rationale: health ok
    tags: [system]
    obligations: {audit: true}
"""

from __future__ import annotations

import asyncio
import dataclasses
import fnmatch
import io
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Tuple

try:
    import yaml  # type: ignore
except Exception:
    yaml = None  # yaml необязателен; json тоже поддерживаем

try:
    import git  # GitPython
except Exception:
    git = None  # fallback через subprocess

try:
    import gnupg  # python-gnupg (обертка поверх gpg)
except Exception:
    gnupg = None

try:
    from pydantic import BaseModel, Field, ValidationError
except Exception:
    BaseModel = object  # type: ignore
    Field = lambda *a, **k: None  # type: ignore
    ValidationError = Exception  # type: ignore

try:
    from prometheus_client import Counter, Gauge, Histogram
except Exception:
    Counter = Gauge = Histogram = None  # type: ignore

try:
    from opentelemetry import trace
    from opentelemetry.trace import Status, StatusCode
except Exception:
    trace = None
    Status = None
    StatusCode = None

logger = logging.getLogger("policy_core.store.gitops")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s gitops %(message)s"))
    logger.addHandler(handler)
logger.setLevel(os.getenv("POLICY_CORE_LOG_LEVEL", "INFO").upper())


# ------------------------ Метрики ------------------------
if Counter and Gauge and Histogram:
    M_SYNC_TOTAL = Counter("policy_gitops_sync_total", "Total sync attempts", ["result"])
    M_SYNC_ERRORS = Counter("policy_gitops_sync_errors_total", "Sync errors", ["stage", "kind"])
    M_SYNC_DURATION = Histogram(
        "policy_gitops_sync_seconds", "Sync duration seconds", buckets=(0.05, 0.1, 0.2, 0.5, 1, 2, 5, 10)
    )
    M_RULES = Gauge("policy_gitops_rules_loaded", "Number of rules loaded", ["tenant"])
    M_REV = Gauge("policy_gitops_revision_info", "Revision numeric surrogate", ["rev"])  # set to 1 for current
else:  # pragma: no cover
    M_SYNC_TOTAL = M_SYNC_ERRORS = M_SYNC_DURATION = M_RULES = M_REV = None  # type: ignore


# ------------------------ Схемы ------------------------
class RuleModel(BaseModel):
    effect: str = Field(..., regex=r"^(allow|deny)$")
    match: Dict[str, Any] = Field(default_factory=dict)
    rationale: str = ""
    obligations: Dict[str, Any] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)


@dataclass(frozen=True)
class PolicySnapshot:
    revision: str
    timestamp: float
    rules_by_tenant: Mapping[str, Tuple[Dict[str, Any], ...]]  # tuple для иммутабельности


Subscriber = Callable[[PolicySnapshot], Awaitable[None]]


@dataclass
class GitAuthConfig:
    mode: str = "none"  # none|token|basic|ssh
    token_env: str = "GIT_TOKEN"  # для mode=token
    username: Optional[str] = None  # для basic
    password_env: Optional[str] = None  # для basic
    ssh_key_path: Optional[Path] = None  # для ssh
    ssh_known_hosts: Optional[Path] = None  # опционально


@dataclass
class GitRepoConfig:
    url: str
    branch: str = "main"
    subdir: str = "policies"  # корень политик
    shallow: bool = True
    depth: int = 10
    poll_interval: float = 15.0  # секунды; 0 — не опрашивать
    timeout: float = 20.0
    allow_patterns: Tuple[str, ...] = ("**/*.yaml", "**/*.yml", "**/*.json")
    verify_commits: bool = False
    verify_files: bool = False  # *.asc рядом
    gpg_homedir: Optional[Path] = None
    required_signers: Optional[Tuple[str, ...]] = None  # отпечатки/uid допущенных подписантов


def _safe_env_get(name: Optional[str]) -> Optional[str]:
    try:
        if not name:
            return None
        return os.environ.get(name)
    except Exception:
        return None


# ------------------------ Утилиты ------------------------
def _is_yaml(path: Path) -> bool:
    return path.suffix.lower() in {".yml", ".yaml"}


def _load_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _load_doc(path: Path) -> List[Dict[str, Any]]:
    text = _load_text(path)
    if _is_yaml(path):
        if yaml is None:
            raise RuntimeError("PyYAML is not installed")
        docs = list(yaml.safe_load_all(text) or [])
    else:
        docs = [json.loads(text)]
    # Документ может быть списком правил или одним правилом
    out: List[Dict[str, Any]] = []
    for d in docs:
        if d is None:
            continue
        if isinstance(d, list):
            out.extend(d)
        else:
            out.append(d)
    return out


def _match_patterns(path: Path, patterns: Iterable[str], base: Path) -> bool:
    rel = str(path.relative_to(base).as_posix())
    return any(fnmatch.fnmatch(rel, p) for p in patterns)


def _tenant_of(path: Path, base: Path) -> str:
    """
    Извлекаем tenant из policies/<tenant>/... ; если нет — 'default'
    """
    try:
        rel = path.relative_to(base)
        parts = rel.parts
        return parts[0] if parts else "default"
    except Exception:
        return "default"


def _now() -> float:
    return time.time()


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f".tmp-{uuid.uuid4().hex}")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def _run(cmd: List[str], cwd: Optional[Path] = None, env: Optional[Dict[str, str]] = None, timeout: Optional[float] = None) -> str:
    res = subprocess.run(cmd, cwd=str(cwd) if cwd else None, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)} | stderr: {res.stderr.strip()}")
    return res.stdout.strip()


# ------------------------ GitOps Backend ------------------------
class GitOpsBackend:
    """
    Асинхронный бэкенд GitOps для загрузки политик.
    """

    def __init__(
        self,
        repo: GitRepoConfig,
        auth: GitAuthConfig = GitAuthConfig(),
        *,
        workdir: Path = Path(".cache/policy-git"),
        state_dir: Path = Path(".cache/policy-state"),
        rate_limit_seconds: float = 2.0,
        backoff_min: float = 0.5,
        backoff_max: float = 30.0,
    ):
        self.repo_cfg = repo
        self.auth = auth
        self.workdir = workdir
        self.state_dir = state_dir
        self.rate_limit_seconds = rate_limit_seconds
        self.backoff_min = backoff_min
        self.backoff_max = backoff_max

        self._repo_dir = self.workdir / "repo"
        self._lock = asyncio.Lock()
        self._subscribers: List[Subscriber] = []
        self._poll_task: Optional[asyncio.Task] = None
        self._last_emit_ts = 0.0
        self._snapshot: Optional[PolicySnapshot] = None
        self._stop_evt = asyncio.Event()

    # ------------- Публичный API -------------
    async def start(self) -> None:
        await self._ensure_repo()
        await self._sync_and_emit()
        if self.repo_cfg.poll_interval > 0:
            self._poll_task = asyncio.create_task(self._poll_loop(), name="gitops-poll")

    async def stop(self) -> None:
        self._stop_evt.set()
        if self._poll_task:
            self._poll_task.cancel()
            with contextlib.suppress(Exception):
                await self._poll_task

    def subscribe(self, cb: Subscriber) -> None:
        self._subscribers.append(cb)

    async def refresh(self) -> None:
        """
        Ручной триггер (например, из webhook).
        С Rate-limit во избежание штормов.
        """
        now = _now()
        if now - self._last_emit_ts < self.rate_limit_seconds:
            return
        await self._sync_and_emit()

    def get_snapshot(self) -> Optional[PolicySnapshot]:
        return self._snapshot

    def get_all_rules(self) -> List[Dict[str, Any]]:
        snap = self._snapshot
        if not snap:
            return []
        all_rules: List[Dict[str, Any]] = []
        for tenant, rules in snap.rules_by_tenant.items():
            all_rules.extend([dict(r) for r in rules])
        return all_rules

    # ------------- Внутренняя логика -------------
    async def _poll_loop(self) -> None:
        backoff = self.backoff_min
        try:
            while not self._stop_evt.is_set():
                try:
                    await self._sync_and_emit()
                    backoff = self.backoff_min
                except Exception as e:
                    if M_SYNC_ERRORS:
                        M_SYNC_ERRORS.labels(stage="poll", kind=type(e).__name__).inc()
                    logger.error(json.dumps({"event": "poll_error", "error": str(e)}))
                    await asyncio.sleep(backoff)
                    backoff = min(self.backoff_max, max(self.backoff_min, backoff * 2))
                await asyncio.wait_for(self._stop_evt.wait(), timeout=self.repo_cfg.poll_interval)
        except asyncio.TimeoutError:
            # обычный путь таймера — продолжаем
            asyncio.create_task(self._poll_loop())
        except asyncio.CancelledError:
            pass

    async def _ensure_repo(self) -> None:
        self.workdir.mkdir(parents=True, exist_ok=True)
        if self._repo_dir.exists() and (self._repo_dir / ".git").exists():
            return
        if git:
            await self._gitpython_clone()
        else:
            await self._git_cli_clone()

    async def _sync_and_emit(self) -> None:
        async with self._lock:
            with _otel_span("gitops.sync") as span, _prom_timer(M_SYNC_DURATION):
                try:
                    rev_before = await self._current_rev()
                    await self._fetch_and_checkout()
                    rev_after = await self._current_rev()
                    if rev_after == rev_before and self._snapshot is not None:
                        M_SYNC_TOTAL and M_SYNC_TOTAL.labels(result="noop").inc()
                        return

                    if self.repo_cfg.verify_commits:
                        self._verify_commit_signatures(rev_after)

                    snapshot = self._build_snapshot()
                    self._persist_last_good(snapshot)
                    self._snapshot = snapshot

                    self._last_emit_ts = _now()
                    await self._notify(snapshot)

                    if M_SYNC_TOTAL:
                        M_SYNC_TOTAL.labels(result="ok").inc()
                    if M_REV:
                        M_REV.labels(rev=snapshot.revision).set(1)
                except Exception as e:
                    if M_SYNC_TOTAL:
                        M_SYNC_TOTAL.labels(result="error").inc()
                    if M_SYNC_ERRORS:
                        M_SYNC_ERRORS.labels(stage="sync_emit", kind=type(e).__name__).inc()
                    logger.error(json.dumps({"event": "sync_emit_error", "error": str(e)}))
                    # попытка отката к последней валидной ревизии
                    fallback = self._load_last_good()
                    if fallback:
                        self._snapshot = fallback
                        await self._notify(fallback)
                    raise

    async def _notify(self, snapshot: PolicySnapshot) -> None:
        for cb in list(self._subscribers):
            try:
                await cb(snapshot)
            except Exception as e:
                logger.error(json.dumps({"event": "subscriber_error", "error": str(e), "rev": snapshot.revision}))

    # ------------- Сборка снапшота -------------
    def _build_snapshot(self) -> PolicySnapshot:
        base = (self._repo_dir / self.repo_cfg.subdir).resolve()
        if not base.exists():
            raise FileNotFoundError(f"Policies dir not found: {base}")
        rules_by_tenant: Dict[str, List[Dict[str, Any]]] = {}
        for path in base.rglob("*"):
            if not path.is_file():
                continue
            if not _match_patterns(path, self.repo_cfg.allow_patterns, base):
                continue
            # проверка подписи файла при необходимости
            if self.repo_cfg.verify_files:
                self._verify_file_signature(path)

            docs = _load_doc(path)
            tenant = _tenant_of(path, base)
            bucket = rules_by_tenant.setdefault(tenant, [])
            for d in docs:
                try:
                    if BaseModel is object:
                        # без pydantic — минимальная проверка
                        eff = str(d.get("effect", "")).lower()
                        if eff not in ("allow", "deny"):
                            raise ValueError("effect must be allow|deny")
                        bucket.append(d)
                    else:
                        model = RuleModel(**d)
                        bucket.append(json.loads(model.json()))
                except ValidationError as ve:
                    raise RuntimeError(f"Validation error in {path}: {ve}") from ve

        # метрики по арендам
        for tenant, rules in rules_by_tenant.items():
            M_RULES and M_RULES.labels(tenant=tenant).set(len(rules))

        rev = self._git_rev_strict()
        snap = PolicySnapshot(
            revision=rev,
            timestamp=_now(),
            rules_by_tenant={k: tuple(map(lambda x: dict(x), v)) for k, v in rules_by_tenant.items()},
        )
        logger.info(json.dumps({"event": "snapshot_built", "rev": rev, "tenants": list(rules_by_tenant.keys())}))
        return snap

    # ------------- Персистентность last_good -------------
    def _persist_last_good(self, snapshot: PolicySnapshot) -> None:
        path = self.state_dir / "last_good.json"
        data = json.dumps(dataclasses.asdict(snapshot), ensure_ascii=False, sort_keys=True).encode("utf-8")
        _atomic_write(path, data)

    def _load_last_good(self) -> Optional[PolicySnapshot]:
        path = self.state_dir / "last_good.json"
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return PolicySnapshot(
                revision=data["revision"],
                timestamp=float(data["timestamp"]),
                rules_by_tenant={k: tuple(map(lambda x: dict(x), v)) for k, v in data["rules_by_tenant"].items()},
            )
        except Exception as e:
            logger.error(json.dumps({"event": "load_last_good_error", "error": str(e)}))
            return None

    # ------------- Проверка GPG-подписей -------------
    def _verify_commit_signatures(self, rev: str) -> None:
        if gnupg is None:
            logger.warning(json.dumps({"event": "gpg_skip", "reason": "python-gnupg not installed"}))
            return
        # Используем `git verify-commit` ради надёжности (требует gpg)
        try:
            _run(["git", "verify-commit", rev], cwd=self._repo_dir)
        except Exception as e:
            raise RuntimeError(f"GPG commit verification failed for {rev}: {e}")

        if self.repo_cfg.required_signers:
            # Проверяем, что подпись сделана одним из разрешённых
            out = _run(["git", "show", "--pretty=full", "--no-patch", rev], cwd=self._repo_dir)
            signer_hit = any(s in out for s in self.repo_cfg.required_signers)
            if not signer_hit:
                raise RuntimeError("Commit signer not in required_signers")

    def _verify_file_signature(self, file_path: Path) -> None:
        if gnupg is None:
            logger.warning(json.dumps({"event": "gpg_skip", "reason": "python-gnupg not installed"}))
            return
        asc = file_path.with_suffix(file_path.suffix + ".asc")
        if not asc.exists():
            raise RuntimeError(f"Missing signature file: {asc}")
        gpg = gnupg.GPG(gnupghome=str(self.repo_cfg.gpg_homedir) if self.repo_cfg.gpg_homedir else None)
        with open(file_path, "rb") as f, open(asc, "rb") as s:
            v = gpg.verify_file(s, str(file_path))
            if not v or not v.valid:
                raise RuntimeError(f"GPG file signature invalid: {file_path}")
            if self.repo_cfg.required_signers and str(v.key_id) not in self.repo_cfg.required_signers:
                raise RuntimeError(f"GPG signer not allowed: {v.key_id}")

    # ------------- Git операции -------------
    async def _gitpython_clone(self) -> None:
        assert git is not None
        env = self._auth_env()
        await asyncio.to_thread(self._gitpython_clone_sync, env)

    def _gitpython_clone_sync(self, env: Dict[str, str]) -> None:
        assert git is not None
        self._repo_dir.mkdir(parents=True, exist_ok=True)
        kwargs = {}
        if self.repo_cfg.shallow:
            kwargs["depth"] = self.repo_cfg.depth
            kwargs["single_branch"] = True
        repo = git.Repo.clone_from(
            self._auth_url(),
            str(self._repo_dir),
            branch=self.repo_cfg.branch,
            env=env,
            **kwargs,
        )
        assert not repo.bare

    async def _git_cli_clone(self) -> None:
        env = os.environ.copy()
        env.update(self._auth_env())
        self._repo_dir.mkdir(parents=True, exist_ok=True)
        args = ["git", "clone"]
        if self.repo_cfg.shallow:
            args += ["--depth", str(self.repo_cfg.depth), "--single-branch", "--branch", self.repo_cfg.branch]
        else:
            args += ["--branch", self.repo_cfg.branch]
        args += [self._auth_url(), str(self._repo_dir)]
        await asyncio.to_thread(_run, args, None, env, self.repo_cfg.timeout)

    async def _fetch_and_checkout(self) -> None:
        if git:
            await asyncio.to_thread(self._gitpython_fetch_checkout_sync)
        else:
            await self._git_cli_fetch_checkout()

    def _gitpython_fetch_checkout_sync(self) -> None:
        assert git is not None
        repo = git.Repo(str(self._repo_dir))
        repo.git.fetch("--all", "--prune")
        repo.git.checkout(self.repo_cfg.branch)
        repo.git.reset("--hard", f"origin/{self.repo_cfg.branch}")

    async def _git_cli_fetch_checkout(self) -> None:
        env = os.environ.copy()
        env.update(self._auth_env())
        await asyncio.to_thread(_run, ["git", "fetch", "--all", "--prune"], self._repo_dir, env, self.repo_cfg.timeout)
        await asyncio.to_thread(_run, ["git", "checkout", self.repo_cfg.branch], self._repo_dir, env, self.repo_cfg.timeout)
        await asyncio.to_thread(_run, ["git", "reset", "--hard", f"origin/{self.repo_cfg.branch}"], self._repo_dir, env, self.repo_cfg.timeout)

    async def _current_rev(self) -> str:
        return await asyncio.to_thread(self._git_rev_strict)

    def _git_rev_strict(self) -> str:
        return _run(["git", "rev-parse", "HEAD"], cwd=self._repo_dir)

    def _auth_env(self) -> Dict[str, str]:
        env: Dict[str, str] = {}
        if self.auth.mode == "ssh":
            ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=yes"]
            if self.auth.ssh_known_hosts:
                ssh_cmd += ["-o", f"UserKnownHostsFile={str(self.auth.ssh_known_hosts)}"]
            if self.auth.ssh_key_path:
                ssh_cmd += ["-i", str(self.auth.ssh_key_path)]
            env["GIT_SSH_COMMAND"] = " ".join(ssh_cmd)
        elif self.auth.mode in ("token", "basic"):
            # Ничего не делаем — токен/логин добавим в URL
            pass
        return env

    def _auth_url(self) -> str:
        url = self.repo_cfg.url
        if self.auth.mode == "token":
            token = _safe_env_get(self.auth.token_env)
            if token and url.startswith("https://") and "@" not in url:
                return re.sub(r"^https://", f"https://oauth2:{token}@", url)
        if self.auth.mode == "basic":
            user = self.auth.username or "user"
            pwd = _safe_env_get(self.auth.password_env) or ""
            if url.startswith("https://") and "@" not in url:
                return re.sub(r"^https://", f"https://{user}:{pwd}@", url)
        return url


# ------------------------ Вспомогательные контексты ------------------------
import contextlib

@contextlib.contextmanager
def _prom_timer(hist: Optional[Histogram]):
    start = time.perf_counter()
    try:
        yield
    finally:
        if hist:
            hist.observe(time.perf_counter() - start)

@contextlib.contextmanager
def _otel_span(name: str):
    if trace:
        with trace.get_tracer("policy_core.store").start_as_current_span(name) as span:
            yield span
    else:
        yield None
