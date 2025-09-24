# neuroforge-core/examples/llm_chat_demo/app.py
# Industrial, stdlib-only LLM chat demo with HTML UI, JSON API and SSE streaming.
# Providers: mock (default) and OpenAI-compatible via env without external deps.

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import email.utils
import http.server
import io
import json
import logging
import logging.handlers
import os
import signal
import socket
import ssl
import sys
import threading
import time
import traceback
import types
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# =========================
# Utilities & configuration
# =========================

ISO = "%Y-%m-%dT%H:%M:%S.%fZ"

def utcnow() -> str:
    return dt.datetime.utcnow().strftime(ISO)

def json_dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

def clamp(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))

@dataclasses.dataclass
class Config:
    host: str = os.getenv("HOST", "127.0.0.1")
    port: int = int(os.getenv("PORT", "8090"))
    cors: Optional[str] = os.getenv("CORS", "*")  # "*" or comma list or None
    log_dir: Path = Path(os.getenv("LOG_DIR", "./logs"))
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    token: Optional[str] = os.getenv("LLM_CHAT_TOKEN")  # Bearer token
    max_request_kb: int = int(os.getenv("MAX_REQUEST_KB", "256"))
    rl_rate: float = float(os.getenv("RATE_LIMIT_RPS", "20"))  # tokens per sec per IP
    rl_burst: float = float(os.getenv("RATE_LIMIT_BURST", "60"))
    provider: str = os.getenv("PROVIDER", "mock")  # mock | openai
    # OpenAI-compatible:
    openai_api_key: Optional[str] = os.getenv("OPENAI_API_KEY")
    openai_base_url: str = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
    openai_model: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    tls_certfile: Optional[Path] = Path(os.getenv("TLS_CERT", "")) if os.getenv("TLS_CERT") else None
    tls_keyfile: Optional[Path] = Path(os.getenv("TLS_KEY", "")) if os.getenv("TLS_KEY") else None

CFG = Config()  # set once at import

# ===============
# JSON logging
# ===============

class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        data = {
            "ts": utcnow(),
            "lvl": record.levelname,
            "msg": record.getMessage(),
            "logger": record.name,
        }
        if hasattr(record, "extra") and isinstance(record.extra, dict):
            data.update(record.extra)
        if record.exc_info:
            data["exc"] = self.formatException(record.exc_info)
        return json_dumps(data)

def setup_logging() -> None:
    CFG.log_dir.mkdir(parents=True, exist_ok=True)
    root = logging.getLogger()
    root.setLevel(getattr(logging, CFG.log_level.upper(), logging.INFO))
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(JsonFormatter())
    root.addHandler(ch)
    fh = logging.handlers.RotatingFileHandler(
        CFG.log_dir / "llm_chat_demo.log", maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    fh.setFormatter(JsonFormatter())
    root.addHandler(fh)

log = logging.getLogger("neuroforge.llm_chat_demo")

# ===============
# Metrics
# ===============

@dataclasses.dataclass
class Counter:
    name: str
    help: str
    value: float = 0.0
    def inc(self, v: float = 1.0) -> None:
        self.value += v

@dataclasses.dataclass
class Gauge:
    name: str
    help: str
    value: float = 0.0
    def set(self, v: float) -> None:
        self.value = v

class Metrics:
    def __init__(self) -> None:
        self.counters: Dict[str, Counter] = {}
        self.gauges: Dict[str, Gauge] = {}
        self._lock = threading.Lock()
    def counter(self, name: str, help: str) -> Counter:
        with self._lock:
            return self.counters.setdefault(name, Counter(name, help))
    def gauge(self, name: str, help: str) -> Gauge:
        with self._lock:
            return self.gauges.setdefault(name, Gauge(name, help))
    def render(self) -> str:
        lines: List[str] = []
        with self._lock:
            for c in self.counters.values():
                lines.append(f"# HELP {c.name} {c.help}")
                lines.append(f"# TYPE {c.name} counter")
                lines.append(f"{c.name} {c.value}")
            for g in self.gauges.values():
                lines.append(f"# HELP {g.name} {g.help}")
                lines.append(f"# TYPE {g.name} gauge")
                lines.append(f"{g.name} {g.value}")
        return "\n".join(lines) + "\n"

METRICS = Metrics()
M_HTTP = METRICS.counter("llm_demo_http_requests_total", "Total HTTP requests")
M_HTTP_ERR = METRICS.counter("llm_demo_http_errors_total", "HTTP error responses")
M_CHAT = METRICS.counter("llm_demo_chat_requests_total", "Chat requests")
M_STREAM = METRICS.counter("llm_demo_chat_stream_requests_total", "Stream chat requests")
M_BYTES_OUT = METRICS.counter("llm_demo_bytes_out_total", "Bytes out")
G_CONN = METRICS.gauge("llm_demo_open_connections", "Open connections")

# ===============
# Rate limiting
# ===============

class TokenBucket:
    def __init__(self, rate: float, burst: float) -> None:
        self.rate = float(rate)
        self.burst = float(burst)
        self.tokens = burst
        self.last = time.time()
        self.lock = threading.Lock()
    def allow(self, cost: float = 1.0) -> bool:
        now = time.time()
        with self.lock:
            self.tokens = min(self.burst, self.tokens + (now - self.last) * self.rate)
            self.last = now
            if self.tokens >= cost:
                self.tokens -= cost
                return True
            return False

RATE_LIMITERS: Dict[str, TokenBucket] = {}

# ===============
# Providers
# ===============

class ChatProvider(typing := object):
    def chat(self, messages: List[Dict[str, str]], temperature: float, max_tokens: int) -> Dict[str, Any]:
        raise NotImplementedError
    def stream(self, messages: List[Dict[str, str]], temperature: float, max_tokens: int):
        """Yield small text chunks (str)."""
        raise NotImplementedError

class MockProvider(ChatProvider):
    def chat(self, messages: List[Dict[str, str]], temperature: float, max_tokens: int) -> Dict[str, Any]:
        prompt = "\n".join(f"{m.get('role','user')}: {m.get('content','')}" for m in messages)[-1000:]
        reply = f"[mock] Received {len(messages)} messages; temp={temperature}; max_tokens={max_tokens}. Echo tail:\n" + prompt
        reply = reply[:max_tokens] if max_tokens > 0 else reply
        return {"role": "assistant", "content": reply, "provider": "mock"}

    def stream(self, messages: List[Dict[str, str]], temperature: float, max_tokens: int):
        text = self.chat(messages, temperature, max_tokens).get("content", "")
        for i in range(0, len(text), 32):
            yield text[i:i+32]
            time.sleep(0.03)

class OpenAICompatProvider(ChatProvider):
    """
    Works with OpenAI-compatible /chat/completions endpoint.
    Requires:
      OPENAI_API_KEY, OPENAI_BASE_URL, OPENAI_MODEL
    Uses urllib from stdlib; supports stream and non-stream.
    """
    def __init__(self, base_url: str, api_key: str, model: str) -> None:
        self.base = base_url.rstrip("/")
        self.key = api_key
        self.model = model

    def _request(self, path: str, payload: Dict[str, Any], stream: bool) -> Any:
        url = f"{self.base}{path}"
        data = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.key}",
        }
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            resp = urllib.request.urlopen(req, timeout=300)  # nosec - demo
            if not stream:
                body = resp.read()
                M_BYTES_OUT.inc(len(body))
                return json.loads(body.decode("utf-8", "ignore"))
            else:
                # Return iterator over lines
                def iter_lines():
                    while True:
                        chunk = resp.readline()
                        if not chunk:
                            break
                        yield chunk
                return iter_lines()
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "ignore")
            raise RuntimeError(f"Upstream error {e.code}: {body}") from None
        except Exception as e:
            raise RuntimeError(f"Upstream error: {e}") from None

    def chat(self, messages: List[Dict[str, str]], temperature: float, max_tokens: int) -> Dict[str, Any]:
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": clamp(temperature, 0.0, 2.0),
            "max_tokens": max(1, min(max_tokens, 8192)),
            "stream": False,
        }
        data = self._request("/chat/completions", payload, stream=False)
        # Try OpenAI-style response
        try:
            choice = data["choices"][0]["message"]
            return {"role": choice.get("role", "assistant"), "content": choice.get("content", ""), "provider": "openai"}
        except Exception:
            # Fall back on simple pass-through
            return {"role": "assistant", "content": json.dumps(data)[:max_tokens], "provider": "openai"}

    def stream(self, messages: List[Dict[str, str]], temperature: float, max_tokens: int):
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": clamp(temperature, 0.0, 2.0),
            "max_tokens": max(1, min(max_tokens, 8192)),
            "stream": True,
        }
        lines = self._request("/chat/completions", payload, stream=True)
        for raw in lines:
            try:
                s = raw.decode("utf-8", "ignore").strip()
                if not s:
                    continue
                if s.startswith("data: "):
                    s = s[6:].strip()
                if s == "[DONE]":
                    break
                obj = json.loads(s)
                delta = obj.get("choices", [{}])[0].get("delta", {})
                piece = delta.get("content", "")
                if piece:
                    yield piece
            except Exception:
                # Skip malformed lines to keep stream alive
                continue

def load_provider() -> ChatProvider:
    if CFG.provider.lower() == "openai":
        if not CFG.openai_api_key:
            log.warning("openai_provider_missing_key")
            return MockProvider()
        return OpenAICompatProvider(CFG.openai_base_url, CFG.openai_api_key, CFG.openai_model)
    return MockProvider()

PROVIDER = load_provider()

# ===============
# HTML UI
# ===============

HTML_INDEX = """<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>NeuroForge LLM Chat Demo</title>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial; margin: 0; background:#0b0f14; color:#e6edf3;}
    header { padding: 12px 16px; background:#111927; border-bottom:1px solid #1f2937;}
    main { display:flex; gap:16px; padding:16px;}
    #left { flex: 2; display:flex; flex-direction:column; gap:12px;}
    #right { flex: 1; background:#0f1720; border:1px solid #1f2937; border-radius:12px; padding:12px; }
    .card { background:#0f1720; border:1px solid #1f2937; border-radius:12px; padding:12px;}
    .row { display:flex; gap:8px;}
    textarea { width:100%; min-height:120px; background:#0b1220; border:1px solid #1f2937; color:#e6edf3; padding:8px; border-radius:8px;}
    input, select { background:#0b1220; border:1px solid #1f2937; color:#e6edf3; padding:6px 8px; border-radius:8px;}
    button { background:#1f6feb; color:white; border:none; padding:8px 12px; border-radius:8px; cursor:pointer;}
    button:disabled { opacity:.6; cursor:not-allowed;}
    pre { white-space:pre-wrap; word-wrap:break-word; }
    .msg { padding:8px; border-radius:8px; margin:6px 0;}
    .user { background:#1b2838;}
    .assistant { background:#132331;}
  </style>
</head>
<body>
  <header><strong>NeuroForge LLM Chat Demo</strong></header>
  <main>
    <section id="left">
      <div class="card">
        <div class="row">
          <label>Temperature <input type="number" id="temperature" min="0" max="2" step="0.1" value="0.3"/></label>
          <label>Max tokens <input type="number" id="max_tokens" min="16" max="4096" step="16" value="512"/></label>
          <label>Stream <select id="stream"><option value="1" selected>yes</option><option value="0">no</option></select></label>
        </div>
        <textarea id="prompt" placeholder="Your message..."></textarea>
        <div class="row">
          <button id="send">Send</button>
          <button id="clear">Clear</button>
        </div>
      </div>
      <div class="card" id="chat"></div>
    </section>
    <aside id="right">
      <h3>Status</h3>
      <div>Health: <span id="health">n/a</span></div>
      <div>Provider: <span id="provider"></span></div>
      <div>Auth: <span id="auth"></span></div>
      <hr/>
      <div><a href="/metrics" target="_blank">/metrics</a></div>
      <div><a href="/healthz" target="_blank">/healthz</a></div>
    </aside>
  </main>
<script>
  const chatBox = document.getElementById('chat');
  const promptEl = document.getElementById('prompt');
  const sendBtn = document.getElementById('send');
  const clearBtn = document.getElementById('clear');
  const tempEl = document.getElementById('temperature');
  const maxEl = document.getElementById('max_tokens');
  const streamEl = document.getElementById('stream');
  const healthEl = document.getElementById('health');
  const providerEl = document.getElementById('provider');
  const authEl = document.getElementById('auth');

  const messages = [];
  providerEl.textContent = "{{PROVIDER}}";
  authEl.textContent = "{{AUTH}}";

  fetch('/healthz').then(r=>r.json()).then(j=>{ healthEl.textContent = j.status; }).catch(()=>{healthEl.textContent='down'});

  clearBtn.onclick = () => { messages.length = 0; chatBox.innerHTML = ''; promptEl.value=''; };

  function push(role, content) {
    const div = document.createElement('div');
    div.className = 'msg ' + role;
    div.textContent = (role==='user' ? 'You: ' : 'Assistant: ') + content;
    chatBox.appendChild(div);
    chatBox.scrollTop = chatBox.scrollHeight;
  }

  sendBtn.onclick = async () => {
    const content = promptEl.value.trim();
    if (!content) return;
    messages.push({role:'user', content});
    push('user', content);
    promptEl.value='';
    sendBtn.disabled = true;

    const body = JSON.stringify({
      messages,
      temperature: parseFloat(tempEl.value || '0.3'),
      max_tokens: parseInt(maxEl.value || '512', 10)
    });

    if (streamEl.value === '1') {
      const resp = await fetch('/api/v1/chat/stream', {method:'POST', headers:{'Content-Type':'application/json'}, body});
      if (!resp.ok) {
        push('assistant', 'Error: ' + resp.status);
        sendBtn.disabled = false;
        return;
      }
      const reader = resp.body.getReader();
      const decoder = new TextDecoder('utf-8');
      let acc = '';
      push('assistant', '');
      const node = chatBox.lastChild;
      while (true) {
        const {value, done} = await reader.read();
        if (done) break;
        const chunk = decoder.decode(value, {stream:true});
        // SSE: data: <text>\n\n
        const lines = chunk.split("\\n\\n");
        for (const ln of lines) {
          if (!ln.startsWith('data:')) continue;
          const text = ln.slice(5).trimStart();
          if (text === '[DONE]') continue;
          acc += text;
          node.textContent = 'Assistant: ' + acc;
        }
      }
      messages.push({role:'assistant', content: acc});
      sendBtn.disabled = false;
    } else {
      const resp = await fetch('/api/v1/chat', {method:'POST', headers:{'Content-Type':'application/json'}, body});
      const j = await resp.json();
      const out = j.output?.content || '(no content)';
      push('assistant', out);
      messages.push({role:'assistant', content: out});
      sendBtn.disabled = false;
    }
  };
</script>
</body>
</html>
"""

# ===============
# HTTP Handler
# ===============

def http_date(ts: float) -> str:
    return email.utils.formatdate(ts, usegmt=True)

def allow_origin(origin: Optional[str]) -> Optional[str]:
    if not CFG.cors:
        return None
    if CFG.cors.strip() == "*":
        return "*"
    for allowed in (o.strip() for o in CFG.cors.split(",")):
        if allowed and origin and allowed == origin:
            return allowed
    return None

class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "NeuroForgeLLMDemo/1.0"
    sys_version = ""

    def _ip(self) -> str:
        return self.client_address[0] if self.client_address else "0.0.0.0"

    def _rate_limit(self, cost: float = 1.0) -> bool:
        ip = self._ip()
        tb = RATE_LIMITERS.get(ip)
        if tb is None:
            tb = RATE_LIMITERS[ip] = TokenBucket(CFG.rl_rate, CFG.rl_burst)
        return tb.allow(cost)

    def _auth_ok(self) -> bool:
        if not CFG.token:
            return True
        h = self.headers.get("Authorization", "")
        return h.startswith("Bearer ") and h.split(" ", 1)[1].strip() == CFG.token

    def _set_common(self, code: int, ctype: str, extra: Dict[str, str] | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Server-Time", utcnow())
        origin = allow_origin(self.headers.get("Origin"))
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Access-Control-Allow-Headers", "Authorization,Content-Type")
            self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
            self.send_header("Access-Control-Max-Age", "600")
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)

    def _deny(self, code: int, msg: str) -> None:
        try:
            payload = {"error": msg, "code": code}
            body = json_dumps(payload).encode("utf-8")
            self._set_common(code, "application/json", {"Content-Length": str(len(body))})
            self.end_headers()
            self.wfile.write(body)
            M_HTTP_ERR.inc(1)
        except Exception:
            pass

    def _read_json(self, limit_bytes: int) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > limit_bytes:
            raise ValueError("Invalid Content-Length")
        data = self.rfile.read(length)
        return json.loads(data.decode("utf-8", "ignore"))

    def do_OPTIONS(self) -> None:
        self._set_common(204, "text/plain")
        self.end_headers()

    def do_GET(self) -> None:
        G_CONN.set(G_CONN.value + 1); M_HTTP.inc(1)
        try:
            if self.path == "/" or self.path.startswith("/index.html"):
                html = HTML_INDEX.replace("{{PROVIDER}}", CFG.provider).replace("{{AUTH}}", "yes" if CFG.token else "no")
                body = html.encode("utf-8")
                self._set_common(200, "text/html; charset=utf-8", {"Content-Length": str(len(body))})
                self.end_headers(); self.wfile.write(body); return

            if self.path.startswith("/healthz"):
                payload = {"status": "ok", "ts": utcnow(), "provider": CFG.provider}
                body = json_dumps(payload).encode("utf-8")
                self._set_common(200, "application/json", {"Content-Length": str(len(body))})
                self.end_headers(); self.wfile.write(body); return

            if self.path.startswith("/metrics"):
                text = METRICS.render().encode("utf-8")
                self._set_common(200, "text/plain; version=0.0.4", {"Content-Length": str(len(text))})
                self.end_headers(); self.wfile.write(text); return

            self._deny(404, "Not Found")
        except Exception:
            log.exception("GET_error", extra={"extra": {"path": self.path}})
            self._deny(500, "Internal Server Error")
        finally:
            G_CONN.set(max(0.0, G_CONN.value - 1))

    def do_POST(self) -> None:
        G_CONN.set(G_CONN.value + 1); M_HTTP.inc(1)
        try:
            if not self._rate_limit():
                self._deny(429, "Too Many Requests"); return
            if not self._auth_ok():
                self._deny(401, "Unauthorized"); return

            if self.path.startswith("/api/v1/chat"):
                if self.path.endswith("/stream"):
                    M_STREAM.inc(1)
                    self._chat_stream()
                    return
                else:
                    M_CHAT.inc(1)
                    self._chat()
                    return

            self._deny(404, "Not Found")
        except Exception:
            log.exception("POST_error", extra={"extra": {"path": self.path}})
            self._deny(500, "Internal Server Error")
        finally:
            G_CONN.set(max(0.0, G_CONN.value - 1))

    # ----- Chat endpoints

    def _parse_chat_body(self) -> Tuple[List[Dict[str, str]], float, int]:
        limit = CFG.max_request_kb * 1024
        body = self._read_json(limit)
        messages = body.get("messages") or []
        if not isinstance(messages, list) or not messages:
            raise ValueError("messages must be a non-empty list")
        # Basic validation & truncation
        clean: List[Dict[str, str]] = []
        total_len = 0
        for m in messages:
            role = str(m.get("role", "user"))
            content = str(m.get("content", ""))[:8000]
            total_len += len(content)
            clean.append({"role": role, "content": content})
        if total_len > 200_000:
            raise ValueError("input too large")
        temperature = float(body.get("temperature", 0.3))
        max_tokens = int(body.get("max_tokens", 512))
        temperature = float(clamp(temperature, 0.0, 2.0))
        max_tokens = int(max(16, min(max_tokens, 4096)))
        return clean, temperature, max_tokens

    def _chat(self) -> None:
        try:
            messages, temperature, max_tokens = self._parse_chat_body()
        except ValueError as e:
            self._deny(400, str(e)); return

        t0 = time.time()
        try:
            out = PROVIDER.chat(messages, temperature, max_tokens)
            payload = {"output": out, "usage": {"latency_ms": int((time.time()-t0)*1000)}}
            body = json_dumps(payload).encode("utf-8")
            self._set_common(200, "application/json", {"Content-Length": str(len(body))})
            self.end_headers(); self.wfile.write(body)
        except Exception as e:
            log.exception("chat_error")
            self._deny(502, f"Upstream failure: {e}")

    def _chat_stream(self) -> None:
        try:
            messages, temperature, max_tokens = self._parse_chat_body()
        except ValueError as e:
            self._deny(400, str(e)); return

        # SSE response
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        origin = allow_origin(self.headers.get("Origin"))
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers()

        try:
            for chunk in PROVIDER.stream(messages, temperature, max_tokens):
                data = f"data: {chunk}\n\n".encode("utf-8")
                self.wfile.write(data); self.wfile.flush()
                M_BYTES_OUT.inc(len(data))
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception as e:
            log.exception("stream_error")
            try:
                self.wfile.write(f"data: [ERROR] {e}\n\n".encode("utf-8"))
                self.wfile.flush()
            except Exception:
                pass

    # Silence default access logs
    def log_message(self, fmt: str, *args: Any) -> None:
        log.debug("access", extra={"extra": {"client": self._ip(), "path": self.path}})

# ===============
# Server builder
# ===============

class ThreadingHTTPServer(http.server.ThreadingHTTPServer):
    def finish_request(self, request, client_address):
        try:
            super().finish_request(request, client_address)
        except Exception:
            log.exception("finish_request_error")

def build_server() -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer((CFG.host, CFG.port), Handler)
    if CFG.tls_certfile and CFG.tls_keyfile:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=str(CFG.tls_certfile), keyfile=str(CFG.tls_keyfile))
        srv.socket = context.wrap_socket(srv.socket, server_side=True)
    return srv

# ===============
# Main
# ===============

def main() -> None:
    setup_logging()
    log.info("llm_chat_demo_start", extra={"extra": {
        "host": CFG.host, "port": CFG.port, "provider": CFG.provider,
        "auth": "yes" if CFG.token else "no", "tls": bool(CFG.tls_certfile and CFG.tls_keyfile)
    }})
    srv = build_server()

    def shutdown(signum=None, frame=None):
        log.info("llm_chat_demo_shutdown", extra={"extra": {"signal": signum}})
        try:
            srv.shutdown()
        except Exception:
            pass

    try:
        signal.signal(signal.SIGINT, shutdown)
        signal.signal(signal.SIGTERM, shutdown)
    except Exception:
        pass

    try:
        srv.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        shutdown()
    finally:
        try:
            srv.server_close()
        except Exception:
            pass
        log.info("llm_chat_demo_stopped")

if __name__ == "__main__":
    main()
