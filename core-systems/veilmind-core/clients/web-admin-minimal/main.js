// veilmind-core/clients/web-admin-minimal/main.js
// -*- coding: utf-8 -*-
/*
  Minimal yet industrial-grade admin client for veilmind-core.

  Security & reliability highlights:
  - AbortController timeouts, retry with exponential backoff + jitter
  - Idempotency-Key for POST, Content-SHA256 via WebCrypto
  - W3C traceparent propagation without external libs
  - Secret-safe console logging (redaction); never logs raw tokens
  - No token persistence (in-memory only); no localStorage usage
  - XSS-safe rendering via textContent; no innerHTML
  - WebSocket test client for subprotocol "veilmind.redact.v1"
*/

(() => {
  "use strict";

  // --------------------------- Configuration ---------------------------

  const Config = {
    apiBase: (window.__VEILMIND_API_BASE__ || "").replace(/\/+$/, "") || "http://localhost:8080",
    // If your WS endpoint differs, adjust here; default guesses ws(s) from apiBase.
    wsBase: null, // autodetect from apiBase if null
    requestTimeoutMs: 10000,
    connectTimeoutMs: 5000,
    retries: 3,
    backoffBaseMs: 200,
    backoffCapMs: 2500,
    retryStatus: new Set([408, 425, 429, 500, 502, 503, 504]),
    logRequests: true,
    logBodies: false, // still redacted
    redactMaxLen: 2048,
  };

  let _authToken = null; // in-memory only

  function setApiBase(url) {
    Config.apiBase = String(url || "").replace(/\/+$/, "");
  }
  function setAuthToken(token) {
    _authToken = token ? String(token) : null;
  }

  // --------------------------- Utilities: security & tracing ---------------------------

  const REDACT_MASK = "[REDACTED]";
  const DENY_KEYS = new Set([
    "authorization","cookie","set-cookie","x-api-key","api_key","apikey",
    "token","access_token","refresh_token","id_token","session","jwt",
    "password","passwd","secret","private_key","client_secret",
  ]);
  const REDACT_PATTERNS = [
    /(?i)bearer\s+[a-z0-9._\-]+/i,
    /\beyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\b/g, // JWT
    /\b\d{13,19}\b/g, // PAN (broad)
    /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, // Email
    /\+?[0-9][0-9\-\s()]{7,}/g, // Phone
    /\b(pwd|pass(word)?|secret|token|key)\b\s*[:=]\s*\S+/gi,
  ];

  function redactText(s, maxLen = Config.redactMaxLen) {
    let out = String(s);
    for (const rx of REDACT_PATTERNS) out = out.replace(rx, REDACT_MASK);
    if (out.length > maxLen) out = out.slice(0, maxLen) + "...(truncated)";
    return out;
  }

  function redactHeaders(h) {
    const out = {};
    for (const [k, v] of Object.entries(h || {})) {
      if (DENY_KEYS.has(k.toLowerCase())) out[k] = REDACT_MASK;
      else out[k] = redactText(String(v), 256);
    }
    return out;
  }

  function randomHex(bytes) {
    const arr = new Uint8Array(bytes);
    crypto.getRandomValues(arr);
    return [...arr].map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  function buildTraceparent() {
    // W3C: version(2)-traceid(32)-spanid(16)-flags(2)
    const traceId = randomHex(16); // 16 bytes => 32 hex
    const spanId = randomHex(8);   // 8 bytes  => 16 hex
    const flags = "01";            // sampled
    return `00-${traceId}-${spanId}-${flags}`;
  }

  async function sha256HexUtf8(s) {
    if (!crypto || !crypto.subtle) return null;
    const enc = new TextEncoder();
    const buf = enc.encode(s);
    const digest = await crypto.subtle.digest("SHA-256", buf);
    return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  function computeBackoff(attempt) {
    const base = Math.min(Config.backoffCapMs, Config.backoffBaseMs * (2 ** (attempt - 1)));
    const jitter = 0.5 * base + Math.floor((crypto.getRandomValues(new Uint8Array(1))[0] / 255) * 0.5 * base);
    return jitter;
  }

  function idempotencyKey() {
    // RFC 4122 v4-like
    const h = randomHex(16);
    return `${h.slice(0,8)}-${h.slice(8,12)}-4${h.slice(13,16)}-a${h.slice(17,20)}-${h.slice(20,32)}`;
  }

  // --------------------------- Transport: safeFetch ---------------------------

  async function safeFetchJSON(path, { method = "GET", body = null, headers = {}, timeoutMs = Config.requestTimeoutMs } = {}) {
    const url = `${Config.apiBase}${path.startsWith("/") ? path : "/" + path}`;
    const methodU = method.toUpperCase();
    const reqHeaders = { Accept: "application/json", ...headers };

    if (body != null && !reqHeaders["Content-Type"]) {
      reqHeaders["Content-Type"] = "application/json";
    }
    if (_authToken) {
      reqHeaders["Authorization"] = `Bearer ${_authToken}`;
    }
    if (methodU === "POST" && !reqHeaders["Idempotency-Key"]) {
      reqHeaders["Idempotency-Key"] = idempotencyKey();
    }
    reqHeaders["traceparent"] = buildTraceparent();

    const bodyString = body != null ? JSON.stringify(body) : null;
    if (bodyString) {
      try {
        const sha = await sha256HexUtf8(bodyString);
        if (sha) reqHeaders["Content-SHA256"] = sha;
      } catch {}
    }

    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), timeoutMs);

    const logReq = () => {
      if (!Config.logRequests) return;
      const base = `FETCH ${methodU} ${url}\nHeaders: ${JSON.stringify(redactHeaders(reqHeaders))}`;
      if (Config.logBodies && bodyString) {
        console.info(base + `\nBody: ${redactText(bodyString)}`);
      } else {
        console.info(base);
      }
    };

    const logResp = (status, respHeaders, respText) => {
      if (!Config.logRequests) return;
      const base = `Response ${status} for ${methodU} ${url}\nHeaders: ${JSON.stringify(redactHeaders(Object.fromEntries(respHeaders)))}`;
      if (Config.logBodies && respText != null) {
        console.info(base + `\nBody: ${redactText(respText)}`);
      } else {
        console.info(base);
      }
    };

    logReq();

    let attempt = 0;
    while (true) {
      attempt++;
      try {
        const res = await fetch(url, {
          method: methodU,
          headers: reqHeaders,
          body: bodyString,
          signal: controller.signal,
          cache: "no-store",
          credentials: "omit",
        });
        let text = null;
        const ct = res.headers.get("content-type") || "";
        if (ct.includes("application/json")) {
          text = await res.text();
          logResp(res.status, res.headers, text);
          if (res.ok) return JSON.parse(text || "{}");
          // retry only idempotent or retryable statuses
          if (Config.retryStatus.has(res.status) && (methodU === "GET" || methodU === "HEAD")) {
            if (attempt <= Config.retries) {
              const d = computeBackoff(attempt);
              await new Promise(r => setTimeout(r, d));
              continue;
            }
          }
          throw new Error(`HTTP ${res.status}: ${redactText(text)}`);
        } else {
          text = await res.text();
          logResp(res.status, res.headers, text);
          if (res.ok) return text;
          if (Config.retryStatus.has(res.status) && (methodU === "GET" || methodU === "HEAD") && attempt <= Config.retries) {
            const d = computeBackoff(attempt);
            await new Promise(r => setTimeout(r, d));
            continue;
          }
          throw new Error(`HTTP ${res.status}: ${redactText(text)}`);
        }
      } catch (e) {
        if (e.name === "AbortError") {
          if (attempt > Config.retries) throw new Error("request timeout");
        } else {
          // network error
          if (attempt > Config.retries) throw e;
        }
        const d = computeBackoff(attempt);
        await new Promise(r => setTimeout(r, d));
      } finally {
        if (attempt > Config.retries) clearTimeout(t);
      }
    }
  }

  // --------------------------- DOM helpers (XSS-safe) ---------------------------

  function qs(sel) { return document.querySelector(sel); }
  function ce(tag, cls) { const n = document.createElement(tag); if (cls) n.className = cls; return n; }
  function setText(node, text) { node.textContent = String(text == null ? "" : text); }
  function pretty(obj) { try { return JSON.stringify(obj, null, 2); } catch { return String(obj); } }

  // --------------------------- UI: Panels ---------------------------

  function buildUI() {
    const root = qs("#app") || document.body;

    // Top config bar
    const bar = ce("div", "cfg");
    bar.style.display = "grid";
    bar.style.gridTemplateColumns = "1fr 1fr auto auto";
    bar.style.gap = "8px";
    bar.style.margin = "12px 0";

    const apiInput = ce("input"); apiInput.type = "url"; apiInput.placeholder = "API Base URL"; apiInput.value = Config.apiBase;
    const tokInput = ce("input"); tokInput.type = "password"; tokInput.placeholder = "Bearer token (not stored)";
    const saveBtn = ce("button"); setText(saveBtn, "Apply");
    const healthBtn = ce("button"); setText(healthBtn, "Check /health");

    bar.append(apiInput, tokInput, saveBtn, healthBtn);

    // Output area
    const out = ce("pre", "out");
    out.style.background = "#0f172a";
    out.style.color = "#e2e8f0";
    out.style.padding = "12px";
    out.style.borderRadius = "8px";
    out.style.whiteSpace = "pre-wrap";
    out.style.minHeight = "120px";

    // Redact form
    const rwrap = ce("div", "redact");
    rwrap.style.marginTop = "12px";
    const rta = ce("textarea");
    rta.rows = 6;
    rta.placeholder = '{"payload":{"email":"john.doe@example.org","card":"4111 1111 1111 1111"}}';
    rta.style.width = "100%";
    const rulesInput = ce("input"); rulesInput.placeholder = "ruleset_id (optional)";
    const rbtn = ce("button"); setText(rbtn, "POST /v1/redact");

    rwrap.append(rta, rulesInput, rbtn);

    // Metrics
    const mbtn = ce("button"); setText(mbtn, "GET /metrics");
    mbtn.style.marginTop = "8px";

    // WS test
    const wsBtn = ce("button"); setText(wsBtn, "WS redact.v1 test");
    wsBtn.style.marginTop = "8px";

    root.append(bar, out, rwrap, mbtn, wsBtn);

    // Handlers
    saveBtn.addEventListener("click", () => {
      setApiBase(apiInput.value);
      setAuthToken(tokInput.value);
      setText(out, `Applied.\napiBase=${Config.apiBase}\nwsBase=${resolveWsBase()}\nToken in memory: ${_authToken ? "yes" : "no"}`);
    });

    healthBtn.addEventListener("click", async () => {
      try {
        const data = await safeFetchJSON("/health", { method: "GET" });
        setText(out, pretty(data));
      } catch (e) {
        setText(out, String(e.message || e));
      }
    });

    rbtn.addEventListener("click", async () => {
      let parsed = null;
      try {
        parsed = JSON.parse(rta.value || "{}");
      } catch {
        setText(out, "Invalid JSON in redact textarea");
        return;
      }
      try {
        const body = { ...parsed };
        if (rulesInput.value) body.ruleset_id = rulesInput.value;
        const data = await safeFetchJSON("/v1/redact", { method: "POST", body });
        setText(out, pretty(data));
      } catch (e) {
        setText(out, String(e.message || e));
      }
    });

    mbtn.addEventListener("click", async () => {
      try {
        const text = await safeFetchJSON("/metrics", { method: "GET", headers: { Accept: "text/plain" } });
        // safeFetchJSON returns text when not JSON
        setText(out, String(text));
      } catch (e) {
        setText(out, String(e.message || e));
      }
    });

    wsBtn.addEventListener("click", () => wsRedactDemo(out));
  }

  // --------------------------- WS client: veilmind.redact.v1 ---------------------------

  function resolveWsBase() {
    if (Config.wsBase) return Config.wsBase;
    try {
      const u = new URL(Config.apiBase);
      const proto = u.protocol === "https:" ? "wss:" : "ws:";
      return `${proto}//${u.host}`;
    } catch {
      return "ws://localhost:8080";
    }
  }

  function wsRedactDemo(outNode) {
    const wsUrl = `${resolveWsBase()}/ws`;
    const subprotocol = "veilmind.redact.v1";
    // Note: browsers can't set custom headers in WebSocket handshake. For auth, server should rely on cookies/session or
    // explicit query parameter by prior agreement. We avoid sending tokens by default.
    const ws = new WebSocket(wsUrl, [subprotocol]);
    ws.binaryType = "arraybuffer";

    const log = (x) => setText(outNode, (outNode.textContent || "") + "\n" + x);

    ws.onopen = () => {
      log(`WS connected: ${wsUrl} [${subprotocol}]`);
      // Send HELLO envelope
      const hello = {
        type: "hello",
        payload: {
          client: "web-admin-minimal",
          version: "1.0.0",
          subprotocol,
          features: [],
        },
      };
      ws.send(JSON.stringify(hello));
      // Then send a redact.request
      const env = {
        type: "redact.request",
        payload: {
          ruleset_id: null,
          profile: null,
          context: null,
          data: {
            email: "john.doe@example.org",
            card: "4111 1111 1111 1111",
            note: "Bearer abcdef123456",
          },
        },
      };
      ws.send(JSON.stringify(env));
    };

    ws.onmessage = (ev) => {
      try {
        const text = typeof ev.data === "string" ? ev.data : new TextDecoder().decode(new Uint8Array(ev.data));
        log("WS message:\n" + redactText(text));
      } catch {
        log("WS message [binary]");
      }
    };

    ws.onerror = (e) => log("WS error");
    ws.onclose = (e) => log(`WS closed code=${e.code} reason=${e.reason || ""}`);
  }

  // --------------------------- Boot ---------------------------

  document.addEventListener("DOMContentLoaded", buildUI);
})();
