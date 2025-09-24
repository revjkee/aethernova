from __future__ import annotations

import asyncio
import base64
import contextlib
import dataclasses
import fcntl
import hashlib
import json
import os
import random
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import typing as t
from dataclasses import dataclass
from pathlib import Path

# --- Опциональные зависимости ---
try:
    import httpx  # type: ignore
except Exception as e:  # pragma: no cover
    raise RuntimeError("OTA updater requires httpx>=0.23") from e

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # type: ignore
    from cryptography.hazmat.primitives.serialization import load_pem_public_key  # type: ignore
except Exception:  # pragma: no cover
    Ed25519PublicKey = None  # type: ignore

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None  # type: ignore

# Метрики (no-op при отсутствии prometheus_client)
try:
    from prometheus_client import Counter, Histogram, Gauge  # type: ignore
except Exception:  # pragma: no cover
    class _Noop:
        def labels(self, *_, **__): return self
        def inc(self, *_): return
        def observe(self, *_): return
        def set(self, *_): return
    Counter = Histogram = Gauge = _Noop  # type: ignore


# ============================
# Конфигурация и модели
# ============================

@dataclass(frozen=True)
class TLSConfig:
    verify: t.Union[bool, str] = True  # True|False|path_to_ca_bundle
    cert: t.Optional[str] = None       # путь к клиентскому сертификату (PEM) для mTLS
    key: t.Optional[str] = None        # путь к приватному ключу (PEM)


@dataclass(frozen=True)
class OTAConfig:
    manifest_url: str                                  # HTTPS/S3 URL на манифест
    work_dir: str = "/var/lib/ota"                     # база состояния OTA
    slots_dir: str = "/var/lib/ota/slots"              # A/B слоты: slots/a, slots/b
    mode: t.Literal["ab", "inplace"] = "ab"
    current_slot_file: str = "/var/lib/ota/current"    # симлинк или файл с именем активного слота
    pending_flag_file: str = "/var/lib/ota/pending"    # признак незавершенного переключения
    state_file: str = "/var/lib/ota/state.json"        # персистентное состояние
    lock_file: str = "/var/lib/ota/ota.lock"           # файловая блокировка
    timeout_s: float = 30.0                             # таймаут сетевых запросов
    connect_timeout_s: float = 5.0
    max_retries: int = 5
    base_backoff_s: float = 0.5
    max_backoff_s: float = 10.0
    chunk_size: int = 1024 * 512                        # 512 KiB
    max_parallel_downloads: int = 3
    tls: TLSConfig = TLSConfig()
    # Публичные ключи Ed25519 в PEM (несколько для ротации)
    ed25519_pubkeys_pem: tuple[str, ...] = tuple()
    # Ограничение размера пакета на диск (MiB) и контроль свободного места
    min_free_space_mib: int = 256
    # Скрипты/команды
    pre_install_hook: t.Optional[str] = None
    post_install_hook: t.Optional[str] = None
    health_probe_cmd: t.Optional[str] = None          # команда для проверки после переключения
    health_probe_timeout_s: float = 20.0
    # Скоростные лимиты (пример: tc/tokenbucket может быть снаружи; здесь — софт-пауза)
    max_download_rate_mib_s: t.Optional[float] = None
    # Дополнительные заголовки к скачиваниям
    headers: tuple[tuple[str, str], ...] = tuple()


@dataclass(frozen=True)
class Component:
    name: str
    type: t.Literal["archive", "file", "container-image"] = "archive"
    url: str = ""
    size: int = 0
    sha256: str = ""
    # delta-патч (опционально)
    delta_from_version: t.Optional[str] = None
    patch_url: t.Optional[str] = None
    patch_algo: t.Optional[t.Literal["bspatch", "zstdiff"]] = None
    # куда ставить
    install_dir: str = "/opt/app"
    # кастомная команда установки (если нужно)
    install_cmd: t.Optional[str] = None
    # режим прав
    mode: int = 0o755


@dataclass(frozen=True)
class Manifest:
    schema_version: str
    build_id: str
    version: str
    created_at: int  # epoch ms
    compatible: dict
    components: tuple[Component, ...]
    signature: str  # base64 подпись JSON canonical без поля signature

    @staticmethod
    def canonical_bytes(raw: dict) -> bytes:
        """Каноническая форма: без поля 'signature', отсортированные ключи, компактный JSON."""
        c = dict(raw)
        c.pop("signature", None)
        return json.dumps(c, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


@dataclass
class UpdateResult:
    ok: bool
    changed: bool
    build_id: str
    version: str
    slot_switched: t.Optional[str] = None
    error: t.Optional[str] = None


# ============================
# Метрики
# ============================

M_OTA_ATTEMPT = Counter("ota_attempt_total", "OTA attempts", ["result"])
M_OTA_BYTES = Counter("ota_download_bytes_total", "Downloaded bytes", ["component"])
H_OTA_TIME = Histogram("ota_duration_seconds", "OTA duration seconds", ["phase"])
G_OTA_LAST_OK_MS = Gauge("ota_last_ok_ms", "Last successful OTA timestamp ms")


# ============================
# Утилиты FS/сеть/хеши
# ============================

def _ensure_dirs(*paths: str) -> None:
    for p in paths:
        Path(p).mkdir(parents=True, exist_ok=True)


def _fsync_dir(path: str) -> None:
    dfd = os.open(path, os.O_DIRECTORY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def _atomically_move(src: str, dst: str) -> None:
    os.replace(src, dst)
    _fsync_dir(os.path.dirname(dst))


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _enough_space(target_dir: str, need_bytes: int, reserve_mib: int) -> bool:
    st = os.statvfs(target_dir)
    free = st.f_bavail * st.f_frsize
    return free >= need_bytes + reserve_mib * 1024 * 1024


def _load_pubkeys(pems: t.Sequence[str]) -> list[Ed25519PublicKey]:
    keys: list[Ed25519PublicKey] = []
    if not Ed25519PublicKey:
        return keys
    for pem in pems:
        try:
            key = load_pem_public_key(pem.encode("utf-8"))
            if not isinstance(key, Ed25519PublicKey):
                continue
            keys.append(key)
        except Exception:
            continue
    return keys


def _verify_signature(manifest_raw: dict, sig_b64: str, keys: t.Sequence[Ed25519PublicKey]) -> bool:
    if not keys:
        # Если ключей нет — считаем небезопасным.
        return False
    payload = Manifest.canonical_bytes(manifest_raw)
    try:
        sig = base64.b64decode(sig_b64)
    except Exception:
        return False
    for k in keys:
        try:
            k.verify(sig, payload)
            return True
        except Exception:
            continue
    return False


@contextlib.contextmanager
def _file_lock(lock_path: str):
    _ensure_dirs(os.path.dirname(lock_path))
    with open(lock_path, "a+") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)


def _json_load(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _json_dump_atomic(path: str, obj: dict) -> None:
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
        f.flush()
        os.fsync(f.fileno())
    _atomically_move(tmp, path)


def _sleep_jittered(base: float, fraction: float = 0.2) -> float:
    return max(0.05, base + random.uniform(-base * fraction, base * fraction))


# ============================
# Основной класс OTA
# ============================

class OTAUpdater:
    """
    Промышленный OTA-апдейтер:
      - Подпись манифеста (Ed25519), проверка хешей компонентов
      - Резюмируемые скачивания, параллельная докачка
      - A/B-слоты с pending/rollback, либо inplace-установка
      - Pre/Post hook'и, health-проба, идемпотентность по build_id
      - Метрики Prometheus (no-op без библиотеки)
    """

    def __init__(self, cfg: OTAConfig) -> None:
        self.cfg = cfg
        _ensure_dirs(cfg.work_dir, cfg.slots_dir)
        self._pubkeys = _load_pubkeys(cfg.ed25519_pubkeys_pem)
        self._client = httpx.AsyncClient(
            http2=True,
            timeout=httpx.Timeout(cfg.timeout_s, connect=cfg.connect_timeout_s),
            verify=cfg.tls.verify,
            cert=(cfg.tls.cert, cfg.tls.key) if cfg.tls.cert and cfg.tls.key else None,
            headers={k: v for k, v in cfg.headers},
        )

    # -------- Публичное API --------

    async def run_once(self, progress: t.Callable[[str, dict], None] | None = None) -> UpdateResult:
        with _file_lock(self.cfg.lock_file):
            return await self._run_locked(progress)

    async def close(self) -> None:
        await self._client.aclose()

    # -------- Внутреннее --------

    async def _run_locked(self, progress: t.Callable[[str, dict], None] | None) -> UpdateResult:
        t0 = time.time()
        try:
            manifest_raw = await self._fetch_manifest()
            manifest = self._parse_manifest(manifest_raw)
            self._emit(progress, "manifest_loaded", {"build_id": manifest.build_id, "version": manifest.version})

            # идемпотентность
            st = self._load_state()
            if st.get("applied_build_id") == manifest.build_id and st.get("status") == "ok":
                M_OTA_ATTEMPT.labels("noop").inc()
                return UpdateResult(ok=True, changed=False, build_id=manifest.build_id, version=manifest.version)

            # подготовка места и слота
            target_slot = self._prepare_slot()
            staging = Path(self.cfg.work_dir) / "staging" / manifest.build_id
            staging.mkdir(parents=True, exist_ok=True)

            # скачивание и проверка
            with H_OTA_TIME.labels("download").time():  # type: ignore
                await self._download_components(manifest, staging, progress)

            # установка
            with H_OTA_TIME.labels("install").time():  # type: ignore
                await self._run_hook(self.cfg.pre_install_hook, env=self._hook_env(manifest, target_slot))
                await self._install_components(manifest, staging, target_slot, progress)
                await self._run_hook(self.cfg.post_install_hook, env=self._hook_env(manifest, target_slot))

            # переключение слота (A/B) или завершение inplace
            switched_slot: t.Optional[str] = None
            if self.cfg.mode == "ab":
                switched_slot = self._switch_slot(target_slot)
                # флаг pending для авто-rollback
                Path(self.cfg.pending_flag_file).write_text(manifest.build_id, encoding="utf-8")
                os.sync()
            else:
                switched_slot = None

            # фиксация состояния
            self._save_state({"status": "installed", "build_id": manifest.build_id, "version": manifest.version})

            # health-проба (если настроена)
            if self.cfg.health_probe_cmd:
                with H_OTA_TIME.labels("health_probe").time():  # type: ignore
                    ok = await self._run_health_probe()
                if not ok:
                    await self._rollback_if_needed(switched_slot)
                    M_OTA_ATTEMPT.labels("health_fail").inc()
                    return UpdateResult(
                        ok=False, changed=True, build_id=manifest.build_id, version=manifest.version,
                        slot_switched=switched_slot, error="Health probe failed"
                    )

            # успех
            if Path(self.cfg.pending_flag_file).exists():
                # очищаем pending после подтверждения
                Path(self.cfg.pending_flag_file).unlink(missing_ok=True)  # type: ignore[attr-defined]
            self._save_state({"status": "ok", "applied_build_id": manifest.build_id, "version": manifest.version})
            G_OTA_LAST_OK_MS.set(int(time.time() * 1000))
            M_OTA_ATTEMPT.labels("success").inc()
            H_OTA_TIME.labels("total").observe(time.time() - t0)  # type: ignore
            return UpdateResult(ok=True, changed=True, build_id=manifest.build_id, version=manifest.version, slot_switched=switched_slot)

        except Exception as e:
            M_OTA_ATTEMPT.labels("error").inc()
            return UpdateResult(ok=False, changed=False, build_id="", version="", error=str(e))

    # -------- Манифест --------

    async def _fetch_manifest(self) -> dict:
        url = self.cfg.manifest_url
        # Простейшая поддержка s3:// — через окружение AWS и boto3/aioboto3 (опционально)
        if url.startswith("s3://"):
            try:
                import aioboto3  # type: ignore
                _, _, bucket_key = url.partition("s3://")
                bucket, _, key = bucket_key.partition("/")
                session = aioboto3.Session()
                async with session.client("s3") as s3:  # type: ignore
                    obj = await s3.get_object(Bucket=bucket, Key=key)
                    data = await obj["Body"].read()
                    return json.loads(data.decode("utf-8"))
            except Exception:
                # fallback: boto3 в пуле потоков
                try:
                    import boto3  # type: ignore

                    def _load() -> dict:
                        s3 = boto3.client("s3")
                        _, _, bucket_key = url.partition("s3://")
                        bucket, _, key = bucket_key.partition("/")
                        resp = s3.get_object(Bucket=bucket, Key=key)
                        return json.loads(resp["Body"].read().decode("utf-8"))

                    return await asyncio.to_thread(_load)
                except Exception as e:
                    raise RuntimeError(f"s3 manifest load failed: {e}")
        # HTTP(S)
        resp = await self._client.get(url)
        resp.raise_for_status()
        return resp.json()

    def _parse_manifest(self, raw: dict) -> Manifest:
        # подпись
        if not _verify_signature(raw, raw.get("signature", ""), self._pubkeys):
            raise RuntimeError("manifest signature verification failed")
        comps = tuple(Component(**c) for c in raw.get("components", []))
        return Manifest(
            schema_version=raw.get("schema_version", "1.0.0"),
            build_id=raw["build_id"],
            version=raw["version"],
            created_at=int(raw.get("created_at", 0)),
            compatible=raw.get("compatible", {}),
            components=comps,
            signature=raw["signature"],
        )

    # -------- Слоты и состояние --------

    def _current_slot(self) -> str:
        p = Path(self.cfg.current_slot_file)
        if p.is_symlink():
            return p.resolve().name
        if p.exists():
            return p.read_text().strip()
        # по умолчанию 'a'
        return "a"

    def _prepare_slot(self) -> str:
        if self.cfg.mode == "inplace":
            return "inplace"
        cur = self._current_slot()
        nxt = "b" if cur == "a" else "a"
        _ensure_dirs(os.path.join(self.cfg.slots_dir, cur), os.path.join(self.cfg.slots_dir, nxt))
        return nxt

    def _switch_slot(self, target_slot: str) -> str:
        cur_file = Path(self.cfg.current_slot_file)
        target_path = Path(self.cfg.slots_dir) / target_slot
        target_path.mkdir(parents=True, exist_ok=True)
        # создаем симлинк/файл атомарно
        tmp = f"{self.cfg.current_slot_file}.tmp"
        try:
            # делаем симлинк
            if os.path.islink(self.cfg.current_slot_file) or not os.path.exists(self.cfg.current_slot_file):
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(tmp)
                os.symlink(str(target_path), tmp)
                os.replace(tmp, self.cfg.current_slot_file)
            else:
                # файл с именем слота
                with open(tmp, "w") as f:
                    f.write(target_slot)
                    f.flush()
                    os.fsync(f.fileno())
                _atomically_move(tmp, self.cfg.current_slot_file)
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp)
        return target_slot

    async def _rollback_if_needed(self, switched_slot: t.Optional[str]) -> None:
        if self.cfg.mode != "ab" or not switched_slot:
            return
        # вернуть предыдущий
        prev = "a" if switched_slot == "b" else "b"
        self._switch_slot(prev)
        Path(self.cfg.pending_flag_file).unlink(missing_ok=True)  # type: ignore[attr-defined]

    def _load_state(self) -> dict:
        return _json_load(self.cfg.state_file)

    def _save_state(self, extra: dict) -> None:
        st = self._load_state()
        st.update(extra)
        _ensure_dirs(os.path.dirname(self.cfg.state_file))
        _json_dump_atomic(self.cfg.state_file, st)

    # -------- Скачивание --------

    async def _download_components(
        self,
        manifest: Manifest,
        staging: Path,
        progress: t.Callable[[str, dict], None] | None,
    ) -> None:
        # простой контроль свободного места: сумма размеров + запас
        need = sum(max(c.size, 0) for c in manifest.components)
        if not _enough_space(str(staging), need, self.cfg.min_free_space_mib):
            raise RuntimeError("not enough disk space for staging")

        sem = asyncio.Semaphore(self.cfg.max_parallel_downloads)
        tasks = []
        for comp in manifest.components:
            tasks.append(asyncio.create_task(self._download_component(comp, staging, sem, progress)))
        await asyncio.gather(*tasks)

    async def _download_component(
        self,
        comp: Component,
        staging: Path,
        sem: asyncio.Semaphore,
        progress: t.Callable[[str, dict], None] | None,
    ) -> None:
        async with sem:
            dst = staging / f"{comp.name}.pkg"
            dst_tmp = staging / f"{comp.name}.pkg.part"

            # возобновление по Range
            headers = {}
            pos = 0
            if dst_tmp.exists():
                pos = dst_tmp.stat().st_size
                headers["Range"] = f"bytes={pos}-"

            # скачиваем с бэкоффом
            backoff = self.cfg.base_backoff_s
            for attempt in range(1, self.cfg.max_retries + 1):
                try:
                    async with self._client.stream("GET", comp.url, headers=headers) as resp:
                        if resp.status_code not in (200, 206):
                            raise RuntimeError(f"HTTP {resp.status_code}")
                        mode = "ab" if pos and resp.status_code == 206 else "wb"
                        with open(dst_tmp, mode) as f:
                            async for chunk in resp.aiter_bytes(self.cfg.chunk_size):
                                f.write(chunk)
                                if self.cfg.max_download_rate_mib_s:
                                    await asyncio.sleep(
                                        len(chunk) / (self.cfg.max_download_rate_mib_s * 1024 * 1024)
                                    )
                                M_OTA_BYTES.labels(comp.name).inc(len(chunk))
                    break
                except Exception as e:
                    if attempt >= self.cfg.max_retries:
                        raise RuntimeError(f"download failed for {comp.name}: {e}")
                    await asyncio.sleep(_sleep_jittered(backoff))
                    backoff = min(self.cfg.max_backoff_s, backoff * 2)

            os.replace(dst_tmp, dst)
            if comp.sha256:
                digest = _sha256_file(str(dst))
                if digest.lower() != comp.sha256.lower():
                    raise RuntimeError(f"sha256 mismatch for {comp.name}")
            self._emit(progress, "download_ok", {"component": comp.name, "bytes": os.path.getsize(dst)})

    # -------- Установка --------

    async def _install_components(
        self,
        manifest: Manifest,
        staging: Path,
        target_slot: str,
        progress: t.Callable[[str, dict], None] | None,
    ) -> None:
        for comp in manifest.components:
            pkg = staging / f"{comp.name}.pkg"
            if not pkg.exists():
                raise RuntimeError(f"staged component missing: {comp.name}")

            install_dir = Path(comp.install_dir)
            if self.cfg.mode == "ab" and target_slot in ("a", "b"):
                install_dir = Path(self.cfg.slots_dir) / target_slot / install_dir.relative_to("/")

            install_dir.mkdir(parents=True, exist_ok=True)

            if comp.install_cmd:
                # кастомная команда, куда подставляем переменные
                cmd = comp.install_cmd.format(
                    PKG=str(pkg),
                    INSTALL_DIR=str(install_dir),
                    NAME=comp.name,
                )
                await self._run_cmd(cmd, timeout=600)
            else:
                # стандартная установка
                if comp.type == "archive":
                    await self._extract_archive(str(pkg), str(install_dir))
                elif comp.type == "file":
                    dst = install_dir / comp.name
                    await asyncio.to_thread(shutil.copyfile, str(pkg), str(dst))
                    os.chmod(dst, comp.mode)
                elif comp.type == "container-image":
                    # best-effort: импорт через ctr, если доступен
                    with contextlib.suppress(Exception):
                        await self._run_cmd(f"ctr -n k8s.io images import {pkg}", timeout=600)
                else:
                    raise RuntimeError(f"unsupported component type: {comp.type}")

            self._emit(progress, "install_ok", {"component": comp.name, "dir": str(install_dir)})

    async def _extract_archive(self, pkg_path: str, dest_dir: str) -> None:
        # Поддерживаем наиболее типичные форматы: .tar.gz, .tgz, .zip
        if pkg_path.endswith((".tar.gz", ".tgz", ".tar")):
            await self._run_cmd(f"tar -xpf {shlex_quote(pkg_path)} -C {shlex_quote(dest_dir)}", timeout=900)
        elif pkg_path.endswith(".zip"):
            await self._run_cmd(f"unzip -o {shlex_quote(pkg_path)} -d {shlex_quote(dest_dir)}", timeout=900)
        else:
            # если это исполняемый файл/скрипт
            st = os.stat(pkg_path)
            if not (st.st_mode & stat.S_IXUSR):
                os.chmod(pkg_path, st.st_mode | stat.S_IXUSR)
            await asyncio.to_thread(shutil.copy2, pkg_path, os.path.join(dest_dir, os.path.basename(pkg_path)))

    # -------- Hooks / Health --------

    def _hook_env(self, manifest: Manifest, slot: str) -> dict:
        env = dict(os.environ)
        env.update({
            "OTA_BUILD_ID": manifest.build_id,
            "OTA_VERSION": manifest.version,
            "OTA_SLOT": slot,
            "OTA_MODE": self.cfg.mode,
        })
        return env

    async def _run_hook(self, cmd: str | None, env: dict | None = None) -> None:
        if not cmd:
            return
        await self._run_cmd(cmd, timeout=600, env=env)

    async def _run_health_probe(self) -> bool:
        if not self.cfg.health_probe_cmd:
            return True
        try:
            await self._run_cmd(self.cfg.health_probe_cmd, timeout=self.cfg.health_probe_timeout_s)
            return True
        except Exception:
            return False

    # -------- Командный раннер --------

    async def _run_cmd(self, cmd: str, timeout: float, env: dict | None = None) -> None:
        proc = await asyncio.create_subprocess_shell(
            cmd, env=env, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            raise RuntimeError(f"command timeout: {cmd}")
        if proc.returncode != 0:
            raise RuntimeError(f"command failed ({proc.returncode}): {cmd}\n{err.decode()}")

    # -------- Уведомления прогресса --------

    @staticmethod
    def _emit(cb: t.Callable[[str, dict], None] | None, event: str, payload: dict) -> None:
        if cb:
            try:
                cb(event, payload)
            except Exception:
                pass


# ============================
# Вспомогательное (shell quoting)
# ============================

def shlex_quote(s: str) -> str:
    # Минимальная реализация для безопасного использования путей в shell-командах
    return "'" + s.replace("'", "'\\''") + "'"


# ============================
# CLI (опционально)
# ============================

async def _main() -> int:  # pragma: no cover
    cfg = OTAConfig(
        manifest_url=os.getenv("OTA_MANIFEST_URL", "https://localhost:8443/ota/manifest.json"),
        work_dir=os.getenv("OTA_WORK_DIR", "/var/lib/ota"),
        slots_dir=os.getenv("OTA_SLOTS_DIR", "/var/lib/ota/slots"),
        mode=os.getenv("OTA_MODE", "ab"),  # ab|inplace
        ed25519_pubkeys_pem=tuple(filter(None, os.getenv("OTA_PUBKEYS_PEM", "").split("|||"))),
        pre_install_hook=os.getenv("OTA_PRE_HOOK"),
        post_install_hook=os.getenv("OTA_POST_HOOK"),
        health_probe_cmd=os.getenv("OTA_HEALTH_PROBE"),
    )
    updater = OTAUpdater(cfg)

    def _print_progress(ev: str, pl: dict) -> None:
        print(json.dumps({"event": ev, **pl}, ensure_ascii=False))

    try:
        res = await updater.run_once(progress=_print_progress)
        print(json.dumps(dataclasses.asdict(res), ensure_ascii=False))
        return 0 if res.ok else 1
    finally:
        await updater.close()

if __name__ == "__main__":  # pragma: no cover
    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        sys.exit(130)
