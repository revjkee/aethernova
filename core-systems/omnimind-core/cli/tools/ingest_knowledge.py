# path: omnimind-core/cli/tools/ingest_knowledge.py
# License: MIT
from __future__ import annotations

import argparse
import asyncio
import concurrent.futures
import contextlib
import fnmatch
import glob
import hashlib
import io
import json
import logging
import mimetypes
import os
import re
import sqlite3
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# ---------------- Optional/Best-effort imports ----------------
try:
    import numpy as np  # type: ignore
except Exception:
    np = None  # type: ignore

try:
    from sentence_transformers import SentenceTransformer  # type: ignore
except Exception:
    SentenceTransformer = None  # type: ignore

try:
    from bs4 import BeautifulSoup  # type: ignore
except Exception:
    BeautifulSoup = None  # type: ignore

try:
    from pdfminer.high_level import extract_text as pdf_extract_text  # type: ignore
except Exception:
    pdf_extract_text = None  # type: ignore

try:
    from tqdm import tqdm  # type: ignore
except Exception:
    tqdm = None  # type: ignore

# Our internal modules (optional presence)
with contextlib.suppress(Exception):
    from omnimind.tools.builtins.web_fetch import WebFetcher  # type: ignore

with contextlib.suppress(Exception):
    from omnimind.utils.idgen import new_ulid  # type: ignore

# Observability latency (optional)
@contextlib.asynccontextmanager
async def _noop_latency(*args, **kwargs):
    yield

try:
    from observability_core.logging.latency.latency_tracker import track_latency  # type: ignore
except Exception:
    track_latency = _noop_latency  # type: ignore

# ---------------- Logging ----------------
LOG = logging.getLogger("ingest_knowledge")

# ---------------- Helpers ----------------
def utcnow() -> datetime:
    return datetime.now(timezone.utc)

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8", errors="replace"))

def gen_id() -> str:
    try:
        return new_ulid()  # type: ignore
    except Exception:
        import uuid
        return uuid.uuid4().hex

def ensure_parent_dir(p: Path) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)

def norm_mime(path: Path) -> str:
    mt, _ = mimetypes.guess_type(str(path))
    return (mt or "application/octet-stream").lower()

def clamp(v: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, v))

# ---------------- Text extraction ----------------
def read_text_file(path: Path, max_bytes: int) -> str:
    data = path.read_bytes()
    if len(data) > max_bytes:
        raise ValueError(f"payload_too_large:{path}")
    try:
        return data.decode("utf-8")
    except Exception:
        return data.decode("utf-8", errors="replace")

def read_markdown(path: Path, max_bytes: int) -> str:
    text = read_text_file(path, max_bytes)
    # strip code fences optionally? keep as-is; simple cleanup of HTML tags inside md
    return text

def read_html(path: Path, max_bytes: int) -> str:
    data = path.read_bytes()
    if len(data) > max_bytes:
        raise ValueError(f"payload_too_large:{path}")
    if BeautifulSoup is None:
        # fallback naive stripping
        try:
            txt = data.decode("utf-8", errors="replace")
        except Exception:
            txt = str(data)
        # crude tag removal
        return re.sub(r"<[^>]+>", " ", txt)
    try:
        txt = data.decode("utf-8", errors="replace")
        soup = BeautifulSoup(txt, "html.parser")
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()
        return soup.get_text(separator="\n", strip=True)
    except Exception:
        return data.decode("utf-8", errors="replace")

def read_pdf(path: Path, max_bytes: int) -> str:
    if pdf_extract_text is None:
        raise RuntimeError("pdf_support_missing: install pdfminer.six")
    size = path.stat().st_size
    if size > max_bytes:
        raise ValueError(f"payload_too_large:{path}")
    return pdf_extract_text(str(path))

def extract_text_from_file(path: Path, max_bytes: int) -> Tuple[str, str]:
    mime = norm_mime(path)
    suffix = path.suffix.lower()
    if suffix in [".txt", ".log", ".csv", ".tsv", ".json", ".yml", ".yaml"]:
        return read_text_file(path, max_bytes), mime
    if suffix in [".md", ".markdown", ".rst"]:
        return read_markdown(path, max_bytes), "text/markdown"
    if suffix in [".html", ".htm", ".xhtml"]:
        return read_html(path, max_bytes), "text/html"
    if suffix in [".pdf"]:
        return read_pdf(path, max_bytes), "application/pdf"
    # default text attempt
    return read_text_file(path, max_bytes), mime

# ---------------- Chunking ----------------
def chunk_text(text: str, chunk_size: int, overlap: int) -> List[str]:
    chunk_size = clamp(chunk_size, 200, 8000)
    overlap = clamp(overlap, 0, max(0, chunk_size - 50))
    if not text:
        return []
    # simple by characters with boundary on whitespace
    chunks: List[str] = []
    i = 0
    n = len(text)
    while i < n:
        j = min(n, i + chunk_size)
        # try not to cut words
        if j < n:
            k = text.rfind(" ", i, j)
            if k != -1 and k - i > chunk_size * 0.6:
                j = k
        chunks.append(text[i:j].strip())
        if j >= n:
            break
        i = max(0, j - overlap)
    return [c for c in chunks if c]

# ---------------- Embedding ----------------
class Embedder:
    def __init__(self) -> None:
        self._model = None
        if SentenceTransformer is not None:
            try:
                # Small, robust default
                self._model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
                self.dim = int(getattr(self._model, "get_sentence_embedding_dimension")() or 384)  # type: ignore
            except Exception:
                self._model = None
        if self._model is None:
            self.dim = 256  # fallback dim

    def embed(self, texts: List[str]) -> Optional[List[bytes]]:
        if not texts:
            return []
        # Prefer real model
        if self._model is not None:
            try:
                vecs = self._model.encode(texts, normalize_embeddings=True, convert_to_numpy=True)  # type: ignore
                if np is not None:
                    return [np.asarray(v, dtype=np.float32).tobytes() for v in vecs]
                # numpy absent: pack as JSON
                return [json.dumps(list(map(float, v))).encode("utf-8") for v in vecs]  # type: ignore
            except Exception as e:
                LOG.warning("Embedding model failed, falling back to hash-embedding: %s", e)
        # Fallback hash-embedding (deterministic)
        return [self._hash_embed(t) for t in texts]

    def _hash_embed(self, text: str) -> bytes:
        # 256-dim simple hashing TF-like embedding: sum of token hashes
        tokens = re.findall(r"\w{2,}", text.lower())
        dim = self.dim
        vec = [0.0] * dim
        for tok in tokens:
            h = int(hashlib.blake2b(tok.encode("utf-8"), digest_size=8).hexdigest(), 16)
            idx = h % dim
            vec[idx] += 1.0
        # L2 normalize
        norm = sum(x * x for x in vec) ** 0.5 or 1.0
        vec = [x / norm for x in vec]
        if np is not None:
            return np.asarray(vec, dtype=np.float32).tobytes()
        return json.dumps(vec).encode("utf-8")

# ---------------- Storage (SQLite) ----------------
DDL = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
CREATE TABLE IF NOT EXISTS documents (
  id TEXT PRIMARY KEY,
  source TEXT NOT NULL,            -- 'file' | 'url'
  uri TEXT NOT NULL,               -- absolute path or normalized URL
  title TEXT,
  mime TEXT,
  sha256 TEXT NOT NULL UNIQUE,
  bytes INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  meta TEXT
);
CREATE INDEX IF NOT EXISTS idx_documents_uri ON documents(uri);
CREATE INDEX IF NOT EXISTS idx_documents_sha ON documents(sha256);

CREATE TABLE IF NOT EXISTS chunks (
  id TEXT PRIMARY KEY,
  doc_id TEXT NOT NULL,
  ord INTEGER NOT NULL,
  text TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY(doc_id) REFERENCES documents(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_chunks_doc ON chunks(doc_id);
CREATE INDEX IF NOT EXISTS idx_chunks_sha ON chunks(sha256);

CREATE TABLE IF NOT EXISTS vectors (
  chunk_id TEXT PRIMARY KEY,
  dim INTEGER NOT NULL,
  data BLOB NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY(chunk_id) REFERENCES chunks(id) ON DELETE CASCADE
);
"""

class Store:
    def __init__(self, db_path: Path) -> None:
        ensure_parent_dir(db_path)
        self.db = sqlite3.connect(str(db_path))
        self.db.execute("PRAGMA foreign_keys=ON;")
        self._init()

    def _init(self) -> None:
        cur = self.db.cursor()
        for stmt in DDL.strip().split(";"):
            s = stmt.strip()
            if s:
                cur.execute(s)
        self.db.commit()

    def has_sha(self, table: str, sha: str) -> bool:
        cur = self.db.execute(f"SELECT 1 FROM {table} WHERE sha256=? LIMIT 1", (sha,))
        return cur.fetchone() is not None

    def upsert_document(
        self,
        *,
        doc_id: str,
        source: str,
        uri: str,
        title: Optional[str],
        mime: str,
        sha: str,
        nbytes: int,
        created_at: datetime,
        meta: Dict[str, Any],
        skip_if_exists: bool = True,
    ) -> bool:
        # returns True if inserted, False if skipped (exists)
        if skip_if_exists:
            cur = self.db.execute("SELECT id FROM documents WHERE sha256=? LIMIT 1", (sha,))
            if cur.fetchone():
                return False
        self.db.execute(
            "INSERT OR IGNORE INTO documents(id, source, uri, title, mime, sha256, bytes, created_at, meta) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                doc_id,
                source,
                uri,
                title,
                mime,
                sha,
                nbytes,
                created_at.isoformat(),
                json.dumps(meta, ensure_ascii=False),
            ),
        )
        self.db.commit()
        return True

    def insert_chunk(self, *, chunk_id: str, doc_id: str, ord_idx: int, text: str, sha: str, created_at: datetime) -> None:
        self.db.execute(
            "INSERT OR IGNORE INTO chunks(id, doc_id, ord, text, sha256, created_at) VALUES (?,?,?,?,?,?)",
            (chunk_id, doc_id, ord_idx, text, sha, created_at.isoformat()),
        )

    def insert_vector(self, *, chunk_id: str, dim: int, blob: bytes, created_at: datetime) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO vectors(chunk_id, dim, data, created_at) VALUES (?,?,?,?)",
            (chunk_id, dim, sqlite3.Binary(blob), created_at.isoformat()),
        )

    def commit(self) -> None:
        self.db.commit()

# ---------------- Title extraction ----------------
def extract_title(text: str, fallback: Optional[str] = None) -> Optional[str]:
    # First markdown header
    m = re.search(r"^\s*#\s+(.+)$", text, flags=re.MULTILINE)
    if m:
        return m.group(1).strip()[:200]
    # HTML title if present in text
    m2 = re.search(r"<title>(.*?)</title>", text, flags=re.IGNORECASE | re.DOTALL)
    if m2:
        return re.sub(r"\s+", " ", m2.group(1)).strip()[:200]
    # First line
    for line in text.splitlines():
        line = line.strip()
        if len(line) > 5:
            return line[:200]
    return fallback

# ---------------- URL ingestion (via WebFetcher) ----------------
async def fetch_url_text(url: str, max_bytes: int) -> Tuple[str, str, bytes, Dict[str, str]]:
    if "WebFetcher" not in globals():
        raise RuntimeError("web_fetch module missing")
    fetcher = WebFetcher()
    async with track_latency("ingest_url_latency_ms", {"kind": "fetch"}):
        res = await fetcher.fetch(url, want="text")
    text = res.text or ""
    # Ensure size limit
    if len(res.content) > max_bytes:
        raise ValueError("payload_too_large:url")
    return res.final_url, res.media_type, res.content, {k.lower(): v for k, v in (res.headers or {}).items()}

# ---------------- File enumeration ----------------
def iter_files(paths: Sequence[str], recursive: bool, follow_symlinks: bool) -> Iterable[Path]:
    seen: set[str] = set()
    for p in paths:
        for fp in glob.glob(p, recursive=recursive):
            path = Path(fp)
            try:
                if path.is_dir():
                    if recursive:
                        for dpath, _, fnames in os.walk(path, followlinks=follow_symlinks):
                            for f in fnames:
                                full = Path(dpath) / f
                                if full.is_file():
                                    key = str(full.resolve())
                                    if key not in seen:
                                        seen.add(key)
                                        yield full
                elif path.is_file():
                    key = str(path.resolve())
                    if key not in seen:
                        seen.add(key)
                        yield path
            except Exception:
                continue

# ---------------- Ingest logic ----------------
@dataclass
class IngestConfig:
    db: Path
    paths: List[str]
    urls: List[str]
    url_file: Optional[Path]
    recursive: bool
    follow_symlinks: bool
    chunk_size: int
    chunk_overlap: int
    max_bytes: int
    embed: bool
    resume: bool
    source_tag: Optional[str]

async def ingest_files(cfg: IngestConfig, store: Store, embedder: Embedder) -> Tuple[int, int, int]:
    total_docs = 0
    total_chunks = 0
    skipped = 0

    files = list(iter_files(cfg.paths, cfg.recursive, cfg.follow_symlinks))
    iterator = tqdm(files, desc="Files") if tqdm else files
    for path in iterator:
        try:
            text, mime = extract_text_from_file(path, cfg.max_bytes)
            data = text.encode("utf-8", errors="replace")
            sha = sha256_bytes(data)
            if cfg.resume and store.has_sha("documents", sha):
                skipped += 1
                continue
            doc_id = gen_id()
            title = extract_title(text, fallback=path.name)
            meta = {"path": str(path.resolve()), "tag": cfg.source_tag}
            inserted = store.upsert_document(
                doc_id=doc_id,
                source="file",
                uri=str(path.resolve()),
                title=title,
                mime=mime,
                sha=sha,
                nbytes=len(data),
                created_at=utcnow(),
                meta=meta,
                skip_if_exists=cfg.resume,
            )
            if not inserted:
                skipped += 1
                continue
            chunks = chunk_text(text, cfg.chunk_size, cfg.chunk_overlap)
            total_docs += 1
            vec_blobs: Optional[List[bytes]] = None
            if cfg.embed and chunks:
                vec_blobs = embedder.embed(chunks)
            for i, ch in enumerate(chunks):
                ch_id = gen_id()
                ch_sha = sha256_text(ch)
                store.insert_chunk(chunk_id=ch_id, doc_id=doc_id, ord_idx=i, text=ch, sha=ch_sha, created_at=utcnow())
                if cfg.embed and vec_blobs:
                    store.insert_vector(chunk_id=ch_id, dim=embedder.dim, blob=vec_blobs[i], created_at=utcnow())
                total_chunks += 1
            store.commit()
        except Exception as e:
            LOG.error("File ingest failed: %s (%s)", path, e)
            continue

    return total_docs, total_chunks, skipped

async def ingest_urls(cfg: IngestConfig, store: Store, embedder: Embedder) -> Tuple[int, int, int]:
    urls = list(cfg.urls)
    if cfg.url_file and cfg.url_file.exists():
        urls += [u.strip() for u in cfg.url_file.read_text(encoding="utf-8").splitlines() if u.strip()]
    if not urls:
        return (0, 0, 0)

    total_docs = 0
    total_chunks = 0
    skipped = 0

    sem = asyncio.Semaphore(8)

    async def process(url: str) -> None:
        nonlocal total_docs, total_chunks, skipped
        try:
            async with sem:
                final_url, media_type, content, headers = await fetch_url_text(url, cfg.max_bytes)
            text = ""
            if media_type.startswith("text/") or media_type in ("application/json", "application/xml", "application/xhtml+xml"):
                try:
                    text = content.decode("utf-8", errors="replace")
                except Exception:
                    text = content.decode("utf-8", errors="replace")
            elif media_type == "application/pdf" and pdf_extract_text is not None:
                # parse PDF content
                try:
                    text = pdf_extract_text(io.BytesIO(content))  # type: ignore[arg-type]
                except Exception:
                    text = ""
            else:
                # fallback: keep raw as text
                text = content.decode("utf-8", errors="replace")
            if not text.strip():
                return
            sha = sha256_bytes(content)
            if cfg.resume and store.has_sha("documents", sha):
                skipped += 1
                return
            doc_id = gen_id()
            title = extract_title(text, fallback=final_url)
            meta = {"url": final_url, "etag": headers.get("etag"), "last_modified": headers.get("last-modified"), "tag": cfg.source_tag}
            inserted = store.upsert_document(
                doc_id=doc_id,
                source="url",
                uri=final_url,
                title=title,
                mime=media_type,
                sha=sha,
                nbytes=len(content),
                created_at=utcnow(),
                meta=meta,
                skip_if_exists=cfg.resume,
            )
            if not inserted:
                skipped += 1
                return
            chunks = chunk_text(text, cfg.chunk_size, cfg.chunk_overlap)
            total_docs += 1
            vec_blobs: Optional[List[bytes]] = None
            if cfg.embed and chunks:
                vec_blobs = embedder.embed(chunks)
            for i, ch in enumerate(chunks):
                ch_id = gen_id()
                ch_sha = sha256_text(ch)
                store.insert_chunk(chunk_id=ch_id, doc_id=doc_id, ord_idx=i, text=ch, sha=ch_sha, created_at=utcnow())
                if cfg.embed and vec_blobs:
                    store.insert_vector(chunk_id=ch_id, dim=embedder.dim, blob=vec_blobs[i], created_at=utcnow())
                total_chunks += 1
            store.commit()
        except Exception as e:
            LOG.error("URL ingest failed: %s (%s)", url, e)

    iterator = tqdm(urls, desc="URLs") if tqdm else urls
    tasks = [asyncio.create_task(process(u)) for u in iterator]
    if tqdm:
        # advance tqdm when task completes
        for t in asyncio.as_completed(tasks):
            await t
            iterator.update(1)  # type: ignore
    else:
        await asyncio.gather(*tasks)

    return total_docs, total_chunks, skipped

# ---------------- CLI ----------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ingest_knowledge", description="Ingest local files and URLs into SQLite + vectors")
    p.add_argument("--db", type=Path, required=True, help="Path to SQLite database file")
    p.add_argument("--path", action="append", default=[], help="Files/dirs/globs to ingest (can repeat)")
    p.add_argument("--url", action="append", default=[], help="URL to ingest (can repeat)")
    p.add_argument("--url-file", type=Path, help="File with list of URLs")
    p.add_argument("--recursive", action="store_true", help="Recurse directories")
    p.add_argument("--follow-symlinks", action="store_true", help="Follow symlinks when recursing")
    p.add_argument("--chunk-size", type=int, default=1200, help="Chunk size in characters (default: 1200)")
    p.add_argument("--chunk-overlap", type=int, default=200, help="Chunk overlap in characters (default: 200)")
    p.add_argument("--max-bytes", type=int, default=8 * 1024 * 1024, help="Per-document max payload (bytes)")
    p.add_argument("--no-embed", action="store_true", help="Do not compute embeddings")
    p.add_argument("--resume", action="store_true", help="Skip documents already present by SHA-256")
    p.add_argument("--source-tag", type=str, help="Optional tag-namespace to attach to metadata")
    p.add_argument("--log-level", type=str, default="INFO", help="DEBUG/INFO/WARN/ERROR")
    return p

async def main_async(args: argparse.Namespace) -> int:
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    cfg = IngestConfig(
        db=Path(args.db),
        paths=list(args.path or []),
        urls=list(args.url or []),
        url_file=args.url_file,
        recursive=bool(args.recursive),
        follow_symlinks=bool(args.follow_symlinks),
        chunk_size=int(args.chunk_size),
        chunk_overlap=int(args.chunk_overlap),
        max_bytes=int(args.max_bytes),
        embed=not bool(args.no_embed),
        resume=bool(args.resume),
        source_tag=args.source_tag,
    )
    store = Store(cfg.db)
    embedder = Embedder()

    total_docs = 0
    total_chunks = 0
    skipped = 0

    if cfg.paths:
        async with track_latency("ingest_files_ms", {"phase": "files"}):
            d, c, s = await ingest_files(cfg, store, embedder)
            total_docs += d
            total_chunks += c
            skipped += s

    if cfg.urls or cfg.url_file:
        async with track_latency("ingest_urls_ms", {"phase": "urls"}):
            d, c, s = await ingest_urls(cfg, store, embedder)
            total_docs += d
            total_chunks += c
            skipped += s

    LOG.info("Done. docs=%s chunks=%s skipped=%s embed_dim=%s", total_docs, total_chunks, skipped, embedder.dim if cfg.embed else 0)
    return 0

def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return asyncio.run(main_async(args))
    except KeyboardInterrupt:
        LOG.warning("Interrupted")
        return 130

if __name__ == "__main__":
    sys.exit(main())
