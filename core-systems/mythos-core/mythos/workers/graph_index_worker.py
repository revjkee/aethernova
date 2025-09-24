# mythos-core/mythos/workers/graph_index_worker.py
# Industrial graph indexing worker for Mythos: incremental text/vectors index, job polling, and HTTP API.
from __future__ import annotations

import asyncio
import base64
import dataclasses
import gc
import hashlib
import json
import math
import os
import re
import signal
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

from fastapi import FastAPI, HTTPException
from fastapi import Body
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# -----------------------------
# Optional YAML support
# -----------------------------
_YAML = None
try:
    import yaml  # type: ignore
    _YAML = yaml
except Exception:
    _YAML = None

# -----------------------------
# Settings (from previous settings.py)
# -----------------------------
try:
    from mythos.settings import get_settings  # type: ignore
except Exception:
    # Fallback minimal settings
    @dataclass
    class _HTTP:
        host: str = "0.0.0.0"
        port: int = 8092
    @dataclass
    class _Worker:
        jobs_root: str = "/data/jobs"
        http_host: str = "0.0.0.0"
        http_port: int = 8092
        concurrency: int = 2
        poll_interval_s: float = 1.0
        stale_reclaim_s: float = 900.0
        log_level: str = "INFO"
    @dataclass
    class _Settings:
        http: _HTTP = _HTTP()
        worker: _Worker = _Worker()
        class _Observ:
            log_level: str = "INFO"
        observability = _Observ()
        class _Paths:
            data_root: str = "/data"
        paths = _Paths()
        class _LLM:
            provider: str = "mock"
            openai_base_url: str = "https://api.openai.com/v1"
            openai_model: str = "text-embedding-3-small"
            openai_api_key: str = os.getenv("OPENAI_API_KEY", "")
        llm = _LLM()
    def get_settings() -> Any:
        return _Settings()

S = get_settings()

# -----------------------------
# Logging middleware (if present)
# -----------------------------
try:
    from mythos.api.http.middleware.logging import RequestLoggingMiddleware  # type: ignore
except Exception:
    RequestLoggingMiddleware = None  # type: ignore

# -----------------------------
# Tokenization / Analyzer
# -----------------------------
_EN_STOP = {
    "a","an","the","and","or","but","if","then","else","for","on","in","at","by","to","of","with","is","are","was","were","be","has","have","had","do","does","did","can","could","should","would","from","as","that","this","these","those","it","its"
}
_RU_STOP = {
    "и","или","но","если","то","иначе","для","на","в","во","от","до","по","из","с","со","без","что","это","эти","тот","та","бы","же","ли","не","нет","да","как","к","у","о"
}
_WORD_RE = re.compile(r"[A-Za-zА-Яа-я0-9]+", re.UNICODE)

def normalize_token(tok: str) -> str:
    return tok.lower()

def tokenize(text: str, lang_hint: Optional[str] = None) -> List[str]:
    toks = [normalize_token(m.group(0)) for m in _WORD_RE.finditer(text or "")]
    if lang_hint and lang_hint.lower().startswith("ru"):
        return [t for t in toks if t not in _RU_STOP and len(t) > 1]
    return [t for t in toks if t not in _EN_STOP and len(t) > 1]

# -----------------------------
# Data models
# -----------------------------
@dataclass
class NodeRef:
    quest_id: str
    node_id: str

@dataclass
class DocUnit:
    doc_id: str                 # quest_id
    path: str
    sha256: str
    title: str
    language: str
    nodes: Dict[str, Dict[str, Any]]  # node_id -> {"text": "...", "meta": {...}}

@dataclass
class Posting:
    doc_id: str
    node_id: str
    tf: float

@dataclass
class IndexSnapshot:
    version: str
    created_at: float
    meta: Dict[str, Any]
    docs: Dict[str, DocUnit]                        # doc_id -> DocUnit
    terms: Dict[str, Dict[str, Any]]                # term -> {"df": int, "idf": float}
    postings: Dict[str, List[Posting]]              # term -> [Posting, ...]
    vectors: Dict[str, List[float]]                 # f"{doc_id}#{node_id}" -> vector

# -----------------------------
# Embeddings Providers
# -----------------------------
class EmbeddingsProvider:
    def embed(self, text: str) -> List[float]:
        raise NotImplementedError

class MockEmbeddings(EmbeddingsProvider):
    def __init__(self, dim: int = 64) -> None:
        self.dim = dim
    def embed(self, text: str) -> List[float]:
        # Deterministic pseudo-embedding from sha256
        h = hashlib.sha256(text.encode("utf-8","replace")).digest()
        # stretch to dim
        out = []
        while len(out) < self.dim:
            for b in h:
                out.append(((b / 255.0) - 0.5) * 2.0)
                if len(out) >= self.dim:
                    break
            h = hashlib.sha256(h).digest()
        # normalize to unit vector
        norm = math.sqrt(sum(x*x for x in out)) or 1.0
        return [x / norm for x in out]

class OpenAIEmbeddings(EmbeddingsProvider):
    def __init__(self, api_key: str, model: str, base_url: str) -> None:
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
    def embed(self, text: str) -> List[float]:
        # Standard library HTTP (no external deps)
        import urllib.request, urllib.error
        payload = {
            "input": text,
            "model": self.model,
        }
        req = urllib.request.Request(
            f"{self.base_url}/embeddings",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type":"application/json","Authorization":f"Bearer {self.api_key}"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30.0) as resp:
                body = json.loads(resp.read().decode("utf-8","replace"))
                vec = body.get("data",[{}])[0].get("embedding")
                if not isinstance(vec, list):
                    raise RuntimeError("invalid embedding payload")
                return [float(x) for x in vec]
        except Exception as e:
            # Fallback: mock embedding on failure
            return MockEmbeddings().embed(text)

def select_embeddings_provider() -> EmbeddingsProvider:
    try:
        if getattr(S.llm, "provider", "mock").lower() == "openai" and getattr(S.llm, "openai_api_key", ""):
            return OpenAIEmbeddings(S.llm.openai_api_key, getattr(S.llm, "openai_model", "text-embedding-3-small"), getattr(S.llm, "openai_base_url", "https://api.openai.com/v1"))
    except Exception:
        pass
    return MockEmbeddings()

# -----------------------------
# Graph loader
# -----------------------------
def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def load_graph_file(path: str) -> Dict[str, Any]:
    text = open(path,"r",encoding="utf-8").read()
    if (path.endswith(".yaml") or path.endswith(".yml")) and _YAML is not None:
        return _YAML.safe_load(text)
    return json.loads(text)

def extract_docunit(raw: Dict[str, Any], path: str) -> DocUnit:
    meta = raw.get("metadata", {}) or {}
    quest_id = meta.get("id") or raw.get("id") or os.path.splitext(os.path.basename(path))[0]
    name = meta.get("name") or raw.get("name") or quest_id
    spec = raw.get("spec", {}) or {}
    i18n = spec.get("i18n", {}) or {}
    default_locale = i18n.get("defaultLocale") or meta.get("locale") or "en-US"
    strings = i18n.get("strings", {}) or {}
    strings_default = strings.get(default_locale, {}) if isinstance(strings, dict) else {}
    graph = spec.get("graph", {}) or {}
    nodes = graph.get("nodes", []) or []
    doc_nodes: Dict[str, Dict[str, Any]] = {}
    def resolve_text(text: Optional[str], text_ref: Optional[str]) -> str:
        if text_ref:
            return strings_default.get(text_ref, text_ref)
        return text or ""
    for n in nodes:
        node_id = n["id"]
        prompt = n.get("prompt", {}) or {}
        p_text = resolve_text(prompt.get("text") or n.get("promptText"), prompt.get("textRef") or n.get("promptTextRef"))
        user_t = prompt.get("userTemplate") or n.get("userTemplate") or ""
        desc = n.get("description") or ""
        # choices texts
        choices = n.get("choices", []) or []
        choice_texts = []
        for c in choices:
            if "textRef" in c:
                choice_texts.append(strings_default.get(c["textRef"], c["textRef"]))
            else:
                choice_texts.append(c.get("text",""))
        text_blob = "\n".join([p_text, user_t, desc] + choice_texts).strip()
        doc_nodes[node_id] = {
            "text": text_blob,
            "meta": {
                "type": n.get("type"),
                "has_choices": bool(choices),
            }
        }
    sha = ""  # to be filled by caller
    return DocUnit(doc_id=quest_id, path=path, sha256=sha, title=name, language=default_locale, nodes=doc_nodes)

# -----------------------------
# Index builder
# -----------------------------
@dataclass
class BuildConfig:
    graphs_root: str
    with_embeddings: bool = False
    bm25_k1: float = 1.5
    bm25_b: float = 0.75

class GraphIndex:
    def __init__(self) -> None:
        self.docs: Dict[str, DocUnit] = {}
        self.terms: Dict[str, Dict[str, Any]] = {}
        self.postings: Dict[str, List[Posting]] = {}
        self.vectors: Dict[str, List[float]] = {}
        self.meta: Dict[str, Any] = {
            "bm25": {"k1": 1.5, "b": 0.75},
            "lang": ["en","ru"],
        }
        self._avgdl: float = 0.0

    def _add_doc(self, doc: DocUnit, provider: Optional[EmbeddingsProvider], cfg: BuildConfig) -> None:
        self.docs[doc.doc_id] = doc
        # Per-node tokenization and posting population
        dl_sum = 0
        for node_id, nd in doc.nodes.items():
            text = nd.get("text","") or ""
            toks = tokenize(text, lang_hint=doc.language)
            dl = len(toks)
            dl_sum += dl
            tf_map: Dict[str, int] = {}
            for t in toks:
                tf_map[t] = tf_map.get(t, 0) + 1
            for t, tf in tf_map.items():
                self.postings.setdefault(t, []).append(Posting(doc_id=doc.doc_id, node_id=node_id, tf=float(tf)))
            # vector
            if provider and cfg.with_embeddings and text.strip():
                key = f"{doc.doc_id}#{node_id}"
                self.vectors[key] = provider.embed(text[:4000])  # cap to avoid long prompts
        # Update average doc length (by node granularity)
        node_count = max(1, len(doc.nodes))
        self._avgdl += (dl_sum / node_count)

    def finalize(self) -> None:
        # Compute IDF
        N = max(1, sum(len(d.nodes) for d in self.docs.values()))  # count by node, not by doc
        self._avgdl = (self._avgdl / max(1, len(self.docs))) if self.docs else 0.0
        for term, plist in self.postings.items():
            df = len(plist)
            idf = math.log((N - df + 0.5) / (df + 0.5) + 1.0)
            self.terms[term] = {"df": df, "idf": idf}

    def bm25_search(self, query: str, top_k: int = 10, lang_hint: Optional[str] = None) -> List[Tuple[str, str, float]]:
        K1 = float(self.meta["bm25"]["k1"])
        B = float(self.meta["bm25"]["b"])
        toks = tokenize(query, lang_hint=lang_hint)
        scores: Dict[Tuple[str,str], float] = {}
        dl_map: Dict[Tuple[str,str], int] = {}
        # Precompute dl per node
        for d in self.docs.values():
            for nid, nd in d.nodes.items():
                dl_map[(d.doc_id, nid)] = len(tokenize(nd.get("text",""), d.language))
        avgdl = (sum(dl_map.values()) / max(1,len(dl_map))) if dl_map else 0.0
        for t in toks:
            term = self.terms.get(t)
            postings = self.postings.get(t, [])
            if not postings or not term:
                continue
            idf = float(term["idf"])
            for p in postings:
                key = (p.doc_id, p.node_id)
                dl = dl_map.get(key, 0)
                tf = p.tf
                denom = tf + K1 * (1 - B + B * (dl / (avgdl or 1.0)))
                score = idf * ((tf * (K1 + 1)) / (denom or 1.0))
                scores[key] = scores.get(key, 0.0) + score
        ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)[:top_k]
        return [(doc_id, node_id, score) for (doc_id, node_id), score in ranked]

    def vector_score(self, query: str, provider: EmbeddingsProvider, top_k: int = 10) -> List[Tuple[str,str,float]]:
        qv = provider.embed(query[:4000])
        # cosine with stored vectors
        scores: List[Tuple[str,str,float]] = []
        for key, v in self.vectors.items():
            # dot because vectors are normalized
            s = sum(a*b for a,b in zip(qv, v))
            doc_id, node_id = key.split("#",1)
            scores.append((doc_id, node_id, float(s)))
        scores.sort(key=lambda x: x[2], reverse=True)
        return scores[:top_k]

    def hybrid_search(self, query: str, provider: Optional[EmbeddingsProvider], k: int = 10, alpha: float = 0.7, lang_hint: Optional[str] = None) -> List[Tuple[str,str,float]]:
        bm = self.bm25_search(query, top_k=max(50,k), lang_hint=lang_hint)
        bm_map: Dict[Tuple[str,str], float] = { (d,n): s for d,n,s in bm }
        vec_map: Dict[Tuple[str,str], float] = {}
        if provider and self.vectors:
            vec = self.vector_score(query, provider, top_k=max(50,k))
            vec_map = { (d,n): s for d,n,s in vec }
        keys = set(list(bm_map.keys()) + list(vec_map.keys()))
        # normalize scores
        def _norm(m: Dict[Tuple[str,str], float]) -> Dict[Tuple[str,str], float]:
            if not m:
                return {}
            vals = list(m.values())
            lo, hi = min(vals), max(vals)
            if hi - lo < 1e-9:
                return {k: 0.0 for k in m}
            return {k: (v - lo) / (hi - lo) for k, v in m.items()}
        bm_n = _norm(bm_map)
        vec_n = _norm(vec_map)
        final: List[Tuple[str,str,float]] = []
        for k2 in keys:
            s = alpha * bm_n.get(k2, 0.0) + (1 - alpha) * vec_n.get(k2, 0.0)
            final.append((k2[0], k2[1], s))
        final.sort(key=lambda x: x[2], reverse=True)
        return final[:k]

# -----------------------------
# Persistence
# -----------------------------
def save_snapshot(path: str, idx: GraphIndex) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    data = {
        "version": "v1",
        "created_at": time.time(),
        "meta": idx.meta,
        "docs": {
            d.doc_id: dataclasses.asdict(d) for d in idx.docs.values()
        },
        "terms": idx.terms,
        "postings": {
            t: [dataclasses.asdict(p) for p in plist] for t, plist in idx.postings.items()
        },
        "vectors": idx.vectors,
    }
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)
    os.replace(tmp, path)

def load_snapshot(path: str) -> Optional[GraphIndex]:
    if not os.path.exists(path):
        return None
    try:
        data = json.load(open(path, "r", encoding="utf-8"))
        idx = GraphIndex()
        idx.meta = data.get("meta", idx.meta)
        # docs
        docs = data.get("docs", {})
        for doc_id, d in docs.items():
            du = DocUnit(
                doc_id=d["doc_id"],
                path=d["path"],
                sha256=d["sha256"],
                title=d.get("title",""),
                language=d.get("language","en-US"),
                nodes=d.get("nodes", {}),
            )
            idx.docs[doc_id] = du
        # postings
        idx.postings = {
            t: [Posting(doc_id=p["doc_id"], node_id=p["node_id"], tf=float(p["tf"])) for p in plist]
            for t, plist in (data.get("postings", {}) or {}).items()
        }
        idx.terms = {t: {"df": int(v["df"]), "idf": float(v["idf"])} for t,v in (data.get("terms", {}) or {}).items()}
        idx.vectors = {k: [float(x) for x in v] for k, v in (data.get("vectors", {}) or {}).items()}
        return idx
    except Exception:
        return None

# -----------------------------
# Builder orchestration
# -----------------------------
@dataclass
class BuildStats:
    scanned: int = 0
    changed: int = 0
    removed: int = 0
    unchanged: int = 0
    errors: int = 0
    duration_s: float = 0.0

def discover_files(root: str) -> List[str]:
    out: List[str] = []
    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            if fn.endswith(".json") or fn.endswith(".yaml") or fn.endswith(".yml"):
                out.append(os.path.join(dirpath, fn))
    return out

def build_index(cfg: BuildConfig, existing: Optional[GraphIndex]) -> Tuple[GraphIndex, BuildStats]:
    t0 = time.perf_counter()
    provider = select_embeddings_provider() if cfg.with_embeddings else None
    idx = existing or GraphIndex()
    # Drop postings/terms/vectors; we will rebuild and reuse docs by change sets
    prev_docs = dict(idx.docs)
    idx.docs = {}
    idx.postings = {}
    idx.terms = {}
    if existing and not cfg.with_embeddings:
        # Keep vectors only if no embeddings rebuild requested
        pass
    else:
        idx.vectors = {}

    files = discover_files(cfg.graphs_root)
    seen_doc_ids: set[str] = set()
    stats = BuildStats()
    for path in files:
        stats.scanned += 1
        try:
            sha = sha256_file(path)
            raw = load_graph_file(path)
            du = extract_docunit(raw, path)
            du.sha256 = sha
            seen_doc_ids.add(du.doc_id)
            prev = prev_docs.get(du.doc_id)
            changed = (prev is None) or (prev.sha256 != du.sha256)
            if changed:
                stats.changed += 1
            else:
                stats.unchanged += 1
            idx._add_doc(du, provider, cfg)
        except Exception:
            stats.errors += 1
            continue
    # Removed docs
    for old_id, old in prev_docs.items():
        if old_id not in seen_doc_ids:
            stats.removed += 1
    # Finalize
    idx.finalize()
    stats.duration_s = time.perf_counter() - t0
    return idx, stats

# -----------------------------
# Job queue (filesystem-based)
# -----------------------------
@dataclass
class Job:
    id: str
    action: str
    payload: Dict[str, Any]
    created_at: float = field(default_factory=lambda: time.time())

class JobQueue:
    def __init__(self, root: str) -> None:
        self.root = root
        os.makedirs(self.root, exist_ok=True)
        self._lock = asyncio.Lock()

    def _job_path(self, job_id: str) -> str:
        return os.path.join(self.root, f"{job_id}.json")

    async def put(self, job: Job) -> None:
        async with self._lock:
            with open(self._job_path(job.id), "w", encoding="utf-8") as f:
                json.dump(dataclasses.asdict(job), f, ensure_ascii=False)

    async def take(self) -> Optional[Job]:
        async with self._lock:
            for fn in sorted(os.listdir(self.root)):
                if not fn.endswith(".json"): 
                    continue
                path = os.path.join(self.root, fn)
                try:
                    data = json.load(open(path, "r", encoding="utf-8"))
                    os.remove(path)
                    return Job(id=data["id"], action=data["action"], payload=data.get("payload", {}), created_at=float(data.get("created_at", time.time())))
                except Exception:
                    # skip invalid job file
                    try: os.remove(path)
                    except Exception: pass
                    continue
        return None

# -----------------------------
# Worker state
# -----------------------------
class WorkerState:
    def __init__(self, index_path: str, graphs_root: str) -> None:
        self.index_path = index_path
        self.graphs_root = graphs_root
        self.idx: Optional[GraphIndex] = load_snapshot(index_path)
        self.status: Dict[str, Any] = {
            "last_build": None,
            "stats": {},
            "version": "v1",
        }
        self.lock = asyncio.Lock()

STATE: Optional[WorkerState] = None

def init_state() -> WorkerState:
    graphs_root = os.getenv("MYTHOS_GRAPHS_ROOT", os.path.join(getattr(S.paths, "data_root", "/data"), "graphs"))
    index_path = os.getenv("MYTHOS_GRAPH_INDEX_PATH", os.path.join(getattr(S.paths, "data_root", "/data"), "index", "graph_index.json"))
    st = WorkerState(index_path=index_path, graphs_root=graphs_root)
    return st

# -----------------------------
# HTTP API
# -----------------------------
class ReindexRequest(BaseModel):
    graphs_root: Optional[str] = Field(default=None)
    with_embeddings: bool = Field(default=False)

class SearchRequest(BaseModel):
    query: str
    top_k: int = Field(default=10, ge=1, le=100)
    alpha: float = Field(default=0.7, ge=0.0, le=1.0)
    doc_id: Optional[str] = None
    lang: Optional[str] = None

def create_app() -> FastAPI:
    app = FastAPI(title="Mythos Graph Index Worker", version="1.0")

    if RequestLoggingMiddleware:
        app.add_middleware(RequestLoggingMiddleware)

    @app.get("/healthz")
    async def healthz() -> Dict[str, Any]:
        return {"status": "ok", "loaded": bool(STATE and STATE.idx is not None)}

    @app.get("/status")
    async def status() -> Dict[str, Any]:
        st = STATE
        if not st:
            raise HTTPException(500, "state not initialized")
        async with st.lock:
            docs = len(st.idx.docs) if st.idx else 0
            terms = len(st.idx.terms) if st.idx else 0
            return {
                "last_build": st.status.get("last_build"),
                "stats": st.status.get("stats", {}),
                "docs": docs,
                "terms": terms,
                "index_path": st.index_path,
                "graphs_root": st.graphs_root,
            }

    @app.post("/reindex")
    async def reindex(req: ReindexRequest = Body(...)) -> Dict[str, Any]:
        st = STATE
        if not st:
            raise HTTPException(500, "state not initialized")
        async with st.lock:
            graphs_root = req.graphs_root or st.graphs_root
            cfg = BuildConfig(graphs_root=graphs_root, with_embeddings=bool(req.with_embeddings))
            idx, stats = build_index(cfg, existing=st.idx if st.idx else None)
            save_snapshot(st.index_path, idx)
            st.idx = idx
            st.graphs_root = graphs_root
            st.status["last_build"] = time.time()
            st.status["stats"] = dataclasses.asdict(stats)
            # GC to free memory after large build
            gc.collect()
            return {"ok": True, "stats": st.status["stats"]}

    @app.post("/search")
    async def search(req: SearchRequest = Body(...)) -> JSONResponse:
        st = STATE
        if not st or not st.idx:
            raise HTTPException(503, "index not built")
        provider = select_embeddings_provider() if st.idx.vectors else None
        async with st.lock:
            if req.doc_id:
                # temporary filtered copy
                sub = GraphIndex()
                sub.meta = st.idx.meta
                # shallow copy selected doc
                if req.doc_id in st.idx.docs:
                    sub.docs[req.doc_id] = st.idx.docs[req.doc_id]
                    # postings/vectors subset
                    for t, plist in st.idx.postings.items():
                        flt = [p for p in plist if p.doc_id == req.doc_id]
                        if flt:
                            sub.postings[t] = flt
                    sub.finalize()
                    for k, v in st.idx.vectors.items():
                        if k.startswith(req.doc_id + "#"): sub.vectors[k] = v
                    idx_ref = sub
                else:
                    idx_ref = st.idx  # fallback
            else:
                idx_ref = st.idx

            results = idx_ref.hybrid_search(req.query, provider=provider, k=req.top_k, alpha=req.alpha, lang_hint=req.lang)
            out = []
            for doc_id, node_id, score in results:
                d = st.idx.docs.get(doc_id)
                text = (d.nodes.get(node_id, {}) or {}).get("text","") if d else ""
                out.append({
                    "doc_id": doc_id,
                    "node_id": node_id,
                    "title": d.title if d else "",
                    "score": round(float(score), 6),
                    "snippet": text[:240],
                    "path": d.path if d else "",
                    "language": d.language if d else "",
                })
            return JSONResponse(status_code=200, content={"results": out})

    return app

# -----------------------------
# Background job loop (optional)
# -----------------------------
async def job_loop(state: WorkerState, stop_event: asyncio.Event) -> None:
    jobs_dir = getattr(S.worker, "jobs_root", "/data/jobs")
    queue = JobQueue(jobs_dir)
    poll = float(getattr(S.worker, "poll_interval_s", 1.0))
    while not stop_event.is_set():
        job = await queue.take()
        if not job:
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=poll)
            except asyncio.TimeoutError:
                continue
            continue
        if job.action == "reindex":
            payload = job.payload or {}
            graphs_root = payload.get("graphs_root") or state.graphs_root
            with_emb = bool(payload.get("with_embeddings", False))
            async with state.lock:
                cfg = BuildConfig(graphs_root=graphs_root, with_embeddings=with_emb)
                idx, stats = build_index(cfg, existing=state.idx if state.idx else None)
                save_snapshot(state.index_path, idx)
                state.idx = idx
                state.graphs_root = graphs_root
                state.status["last_build"] = time.time()
                state.status["stats"] = dataclasses.asdict(stats)
        # other actions can be added here

# -----------------------------
# Main
# -----------------------------
def _install_signal_handlers(loop: asyncio.AbstractEventLoop, stop_event: asyncio.Event) -> None:
    def _sig(*_a: Any, **_kw: Any) -> None:
        stop_event.set()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _sig)
        except NotImplementedError:
            signal.signal(sig, lambda *_: stop_event.set())

def run() -> None:
    global STATE
    STATE = init_state()
    app = create_app()
    # Optionally run job loop alongside ASGI server if executed via uvicorn/hypercorn externally
    stop_event = asyncio.Event()
    loop = asyncio.get_event_loop()
    _install_signal_handlers(loop, stop_event)
    # If run as "python graph_index_worker.py" — start uvicorn inline
    if os.getenv("MYTHOS_STANDALONE", "true").lower() in ("1","true","yes"):
        try:
            import uvicorn  # type: ignore
        except Exception:
            print("uvicorn is required for standalone run. Install 'uvicorn'.", file=sys.stderr)
            sys.exit(2)
        # schedule background loop
        loop.create_task(job_loop(STATE, stop_event))
        uvicorn.run(app, host=getattr(S.worker, "http_host", "0.0.0.0"), port=int(getattr(S.worker, "http_port", 8092)))
    else:
        # When imported by ASGI server, expose 'app' and an init task to start job loop
        async def lifespan(app: FastAPI):
            loop.create_task(job_loop(STATE, stop_event))
            yield
            stop_event.set()
        app.router.lifespan_context = lifespan  # type: ignore
        # Expose app variable for ASGI servers
        globals()["app"] = app

if __name__ == "__main__":
    run()
