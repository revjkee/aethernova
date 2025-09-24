# omnimind-core/omnimind/tools/builtins/file_read.py
# Industrial-grade safe file reader Tool for Omnimind.
# Copyright (c) 2025.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
import base64
import io
import mimetypes
import os
from pathlib import Path
import re
import stat as statmod
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any, Dict, Iterable, Literal, Optional, Tuple

from pydantic import BaseModel, Field, ConfigDict, ValidationError, field_validator

# Совместимость с промышленным invoker'ом
from omnimind.executor.tool_invoker import Tool, ToolInvocationContext, ToolValidationError


def _utc_iso(dt: datetime | float) -> str:
    if isinstance(dt, (int, float)):
        dt = datetime.fromtimestamp(dt, tz=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


# ==========================
# Конфигурация/валидация параметров
# ==========================

_DEFAULT_DENY_PATTERNS = [
    r"(^|/)\.env(\..*)?$",
    r"(^|/)\.git($|/)",
    r"(^|/)\.ssh($|/)",
    r"(^|/)id_rsa(\.pub)?$",
    r"\.(pem|key|p12|pfx)$",
    r"(^|/)shadow$",
    r"(^|/)passwd$",
]

class FileReadParams(BaseModel):
    """
    Параметры безопасного чтения файлов.
    """
    model_config = ConfigDict(extra="forbid")

    # Путь к файлу. Относительный — относительно выбранного root.
    path: str = Field(..., min_length=1, max_length=4096, description="Путь к файлу (abs или относительный)")
    # Алиас корня (см. FileReadTool.allowed_roots) или абсолютный путь (будет проверен на вхождение в allowlist).
    root: Optional[str] = Field(
        default=None,
        description="Алиас разрешенного корня (например, 'data', 'tmp'). Если path абсолютный — будет проверен на allowlist."
    )

    mode: Literal["text", "binary"] = Field(default="text", description="Режим чтения")
    # Срез в байтах (для mode=binary и также для text до декодирования)
    offset: int = Field(default=0, ge=0)
    length: Optional[int] = Field(default=None, ge=1, le=10 * 1024 * 1024, description="Макс. байт для чтения")
    # Построчные режимы для 'text'. Если задан head_lines/tail_lines — length игнорируется.
    head_lines: Optional[int] = Field(default=None, ge=1, le=20000)
    tail_lines: Optional[int] = Field(default=None, ge=1, le=20000)

    # Кодировка текста: если None и detect_encoding=true — автоопределение, иначе 'utf-8'
    encoding: Optional[str] = None
    detect_encoding: bool = True

    # Лимиты защиты
    max_return_bytes: int = Field(default=5 * 1024 * 1024, ge=1, le=50 * 1024 * 1024, description="Ограничение объема возвращаемых данных")
    max_file_size_mb: int = Field(default=100, ge=1, le=1024, description="Макс. размер файла (MB) без явного length")

    # Безопасность
    follow_symlinks: bool = Field(default=False, description="Разрешить чтение через symlink (по умолчанию запрещено)")
    deny_patterns: list[str] = Field(default_factory=list, description="Доп. регулярные выражения deny-листа")

    # Метаданные
    include_stat: bool = True
    include_hash: bool = True
    include_mime: bool = True

    @field_validator("path")
    @classmethod
    def _no_null_bytes(cls, v: str) -> str:
        if "\x00" in v:
            raise ValueError("Invalid path")
        return v

    @field_validator("tail_lines")
    @classmethod
    def _mutual_exclusive_lines(cls, v: Optional[int], info):
        head = info.data.get("head_lines")
        if v and head:
            raise ValueError("head_lines and tail_lines are mutually exclusive")
        return v


@dataclass
class _ResolvedPath:
    root_alias: str
    root_path: Path
    file_path: Path  # абсолютный путь к файлу


# ==========================
# Утилиты безопасности и чтения
# ==========================

def _compile_patterns(patterns: Iterable[str]) -> list[re.Pattern]:
    compiled: list[re.Pattern] = []
    for p in patterns:
        try:
            compiled.append(re.compile(p))
        except re.error:
            # игнорируем неверные шаблоны deny-листа
            continue
    return compiled


def _violates_deny(path: Path, deny_regexes: list[re.Pattern]) -> Optional[str]:
    norm = str(path.as_posix())
    for rgx in deny_regexes:
        if rgx.search(norm):
            return rgx.pattern
    return None


def _resolve_safe_path(
    path: str,
    allowed_roots: dict[str, Path],
    root_alias: Optional[str],
    follow_symlinks: bool,
) -> _ResolvedPath:
    """
    Разрешает путь, жестко ограничивая его allowlist корней и запрещая traversal.
    """
    if not allowed_roots:
        raise ToolValidationError("Allowed roots are not configured")

    if root_alias:
        if root_alias not in allowed_roots:
            raise ToolValidationError(f"Unknown root alias: {root_alias}")
        root = allowed_roots[root_alias]
        base = root
        candidate = (base / path).resolve(strict=False) if not Path(path).is_absolute() else Path(path).resolve(strict=False)
    else:
        # Если алиас не задан: если относительный — используем первый root; если абсолютный — проверим принадлежность
        first_alias, root = next(iter(allowed_roots.items()))
        base = root if isinstance(root, Path) else allowed_roots[first_alias]
        candidate = (base / path).resolve(strict=False) if not Path(path).is_absolute() else Path(path).resolve(strict=False)
        root_alias = first_alias

    # Проверка вхождения в allowlist корня (после resolve)
    try:
        root_real = base.resolve(strict=True)
    except FileNotFoundError:
        # Корень должен существовать
        raise ToolValidationError(f"Root path does not exist: {base}")

    # Нельзя выйти за пределы root
    try:
        candidate_rel = candidate.relative_to(root_real)
    except ValueError:
        # Если path абсолютный внутри другого root — проверим все корни
        for alias, allowed in allowed_roots.items():
            try:
                if candidate.resolve(strict=False).is_relative_to(allowed.resolve(strict=True)):  # py3.9+: emulate if not available
                    root_alias = alias
                    root_real = allowed.resolve(strict=True)
                    candidate_rel = candidate.resolve(strict=False).relative_to(root_real)
                    break
            except Exception:
                continue
        else:
            raise ToolValidationError("Path is outside of allowed roots")

    candidate_abs = (root_real / candidate_rel).resolve(strict=False)

    # Блокируем symlink'и по пути (если запрещены)
    if not follow_symlinks:
        walk = root_real
        for part in candidate_rel.parts:
            walk = walk / part
            try:
                st = os.lstat(walk)
            except FileNotFoundError:
                # конечного файла может не быть; проверили все существующие части
                break
            if statmod.S_ISLNK(st.st_mode):
                raise ToolValidationError("Symlinks are not allowed")

    return _ResolvedPath(root_alias=root_alias, root_path=root_real, file_path=candidate_abs)


async def _stat_path(p: Path) -> Dict[str, Any]:
    def _inner() -> Dict[str, Any]:
        st = p.stat()
        return {
            "size": st.st_size,
            "mode": oct(st.st_mode & 0o777),
            "uid": st.st_uid,
            "gid": st.st_gid,
            "inode": getattr(st, "st_ino", None),
            "mtime": _utc_iso(st.st_mtime),
        }
    return await asyncio.to_thread(_inner)


async def _read_bytes_range(p: Path, offset: int, length: Optional[int], max_return: int) -> Tuple[bytes, bool]:
    """
    Читает байтовый диапазон. Возвращает (data, truncated).
    """
    def _inner() -> Tuple[bytes, bool]:
        with open(p, "rb") as f:
            f.seek(offset, io.SEEK_SET)
            to_read = length if length is not None else max_return
            # читаем на байт больше, чтобы понять, что порезали
            buf = f.read(min(to_read, max_return) + 1)
            truncated = len(buf) > min(to_read, max_return)
            data = buf[: min(to_read, max_return)]
            return data, truncated
    return await asyncio.to_thread(_inner)


def _detect_encoding(sample: bytes) -> Tuple[str, float]:
    """
    Возвращает (encoding, confidence). Пытается использовать charset-normalizer, затем chardet.
    """
    try:
        from charset_normalizer import from_bytes  # type: ignore
        res = from_bytes(sample)
        best = res.best()
        if best and best.encoding:
            return best.encoding, float(best.alphabets_prob or 0.6)
    except Exception:
        pass
    try:
        import chardet  # type: ignore
        guess = chardet.detect(sample)
        enc = guess.get("encoding") or "utf-8"
        conf = float(guess.get("confidence") or 0.5)
        return enc, conf
    except Exception:
        return "utf-8", 0.0
    return "utf-8", 0.0


async def _read_text_head(p: Path, lines: int, max_bytes: int, encoding_hint: Optional[str], detect: bool) -> Tuple[str, str, bool]:
    """
    Возвращает (text, encoding, truncated)
    """
    # читаем кусок начала файла
    data, trunc = await _read_bytes_range(p, 0, None, max_bytes)
    enc = encoding_hint or ("utf-8")
    if detect and not encoding_hint:
        enc, _ = _detect_encoding(data[: min(65536, len(data))])
    text = data.decode(enc, errors="replace")
    out_lines = text.splitlines()
    truncated = trunc or (len(out_lines) > lines)
    return "\n".join(out_lines[:lines]), enc, truncated


async def _read_text_tail(p: Path, lines: int, max_bytes: int, encoding_hint: Optional[str], detect: bool) -> Tuple[str, str, bool]:
    size = (await asyncio.to_thread(lambda: p.stat().st_size))
    start = max(0, size - max_bytes)
    data, trunc = await _read_bytes_range(p, start, None, max_bytes)
    enc = encoding_hint or ("utf-8")
    if detect and not encoding_hint:
        enc, _ = _detect_encoding(data[: min(65536, len(data))])
    text = data.decode(enc, errors="replace")
    out_lines = text.splitlines()
    tail = out_lines[-lines:] if lines < len(out_lines) else out_lines
    # усечение, если мы прочитали не весь файл
    truncated = trunc or (len(out_lines) > lines)
    return "\n".join(tail), enc, truncated


# ==========================
# Инструмент
# ==========================

class FileReadTool(Tool[FileReadParams, Dict[str, Any]]):
    """
    Безопасное чтение файла (text/binary) из ограниченного набора корней.
    Возвращает контент и метаданные, не раскрывая секреты из deny-листа.
    """
    name = "file_read"
    description = "Safely read a file with allowlisted roots, anti-traversal and limits."
    params_model = FileReadParams

    # Политики по умолчанию (могут быть переопределены при создании экземпляра)
    max_concurrency = 16
    rate_limit_per_minute = 240
    default_timeout_s = 5.0
    scope = "fs.read"  # при желании проверяйте в ToolInvocationContext.scopes

    def __init__(self, *, allowed_roots: dict[str, str | Path] | None = None, deny_patterns: Iterable[str] | None = None):
        super().__init__()
        # Карту алиасов приводим к Path и резолвим
        if allowed_roots is None:
            # Безопасные дефолты: текущая директория и /tmp
            allowed_roots = {
                "cwd": Path.cwd(),
                "tmp": Path("/tmp"),
            }
        self.allowed_roots: dict[str, Path] = {k: Path(v) for k, v in allowed_roots.items()}
        self._deny_regex = _compile_patterns([*_DEFAULT_DENY_PATTERNS, *(deny_patterns or [])])

    async def __call__(self, params: FileReadParams, ctx: ToolInvocationContext) -> Dict[str, Any]:
        # Разрешаем путь и проверяем ограничения
        resolved = _resolve_safe_path(
            path=params.path,
            allowed_roots=self.allowed_roots,
            root_alias=params.root,
            follow_symlinks=params.follow_symlinks,
        )

        # deny-list
        violated = _violates_deny(resolved.file_path, self._deny_regex)
        if violated:
            raise ToolValidationError("Access denied by policy", details={"pattern": violated})

        # существование файла
        exists = await asyncio.to_thread(resolved.file_path.exists)
        if not exists:
            raise ToolValidationError("File does not exist")

        # файл ли это
        is_file = await asyncio.to_thread(resolved.file_path.is_file)
        if not is_file:
            raise ToolValidationError("Path is not a regular file")

        # stat и лимиты
        st = await asyncio.to_thread(resolved.file_path.stat)
        file_size = st.st_size
        if params.length is None and params.head_lines is None and params.tail_lines is None:
            # нет явного ограничения чтения — проверяем общий размер
            if file_size > params.max_file_size_mb * 1024 * 1024:
                raise ToolValidationError(f"File is too large (> {params.max_file_size_mb} MB). Use length/head_lines/tail_lines.")

        # чтение
        read_truncated = False
        encoding_used: Optional[str] = None
        content_bytes: Optional[bytes] = None
        text_out: Optional[str] = None

        if params.mode == "binary":
            content_bytes, read_truncated = await _read_bytes_range(
                resolved.file_path, params.offset, params.length, params.max_return_bytes
            )
        else:
            if params.head_lines:
                text_out, encoding_used, read_truncated = await _read_text_head(
                    resolved.file_path, params.head_lines, params.max_return_bytes, params.encoding, params.detect_encoding
                )
            elif params.tail_lines:
                text_out, encoding_used, read_truncated = await _read_text_tail(
                    resolved.file_path, params.tail_lines, params.max_return_bytes, params.encoding, params.detect_encoding
                )
            else:
                # текст по срезу байт
                content_bytes, read_truncated = await _read_bytes_range(
                    resolved.file_path, params.offset, params.length, params.max_return_bytes
                )
                enc = params.encoding or "utf-8"
                if params.detect_encoding and not params.encoding:
                    enc, _ = _detect_encoding(content_bytes[: min(65536, len(content_bytes))])
                encoding_used = enc
                try:
                    text_out = content_bytes.decode(enc, errors="replace")
                except Exception:
                    # fallback
                    text_out = content_bytes.decode("utf-8", errors="replace")
                    encoding_used = enc or "utf-8"

        # mime
        mime_type: Optional[str] = None
        if params.include_mime:
            mime_type = mimetypes.guess_type(resolved.file_path.name)[0] or ("text/plain" if params.mode == "text" else "application/octet-stream")

        # hash/etag по прочитанным данным (или по файлу, если построчный режим)
        hash_hex: Optional[str] = None
        if params.include_hash:
            if params.mode == "text" and (params.head_lines or params.tail_lines):
                # в построчных режимах хэшируем возвращаемый текст
                hash_hex = sha256((text_out or "").encode("utf-8", errors="replace")).hexdigest()
            else:
                buf = content_bytes if content_bytes is not None else (text_out or "").encode("utf-8", errors="replace")
                hash_hex = sha256(buf).hexdigest()
        etag = f"\"{hash_hex}\"" if hash_hex else None

        # упаковка ответа
        result: Dict[str, Any] = {
            "path": str(resolved.file_path),
            "root": resolved.root_alias,
            "mode": params.mode,
            "offset": params.offset,
            "length": (len(content_bytes) if content_bytes is not None else (len(text_out.encode("utf-8")) if text_out is not None else 0)),
            "truncated": read_truncated,
            "mime": mime_type,
            "etag": etag,
        }

        if params.include_stat:
            result["stat"] = {
                "size": file_size,
                "mtime": _utc_iso(st.st_mtime),
                "inode": getattr(st, "st_ino", None),
                "uid": st.st_uid,
                "gid": st.st_gid,
                "mode": oct(st.st_mode & 0o777),
            }

        if params.include_hash and hash_hex:
            result["hash"] = {"algo": "sha256", "hex": hash_hex}

        if params.mode == "binary":
            # кодируем в base64
            b64 = base64.b64encode(content_bytes or b"").decode("ascii")
            result["bytes_base64"] = b64
        else:
            result["encoding"] = encoding_used or "utf-8"
            result["text"] = text_out if text_out is not None else (content_bytes or b"").decode(encoding_used or "utf-8", errors="replace")

        return result


# ==========================
# Хелпер регистрации
# ==========================

def build_file_read_tool(*, roots: dict[str, str | Path] | None = None) -> FileReadTool:
    """
    Создает инструмент file_read с указанными разрешенными корнями.
    Пример:
        tool = build_file_read_tool(roots={"data": "/var/lib/omnimind/data", "tmp": "/tmp"})
        inv.register(tool, alias="file_read")
    """
    return FileReadTool(allowed_roots=roots)
