/* cybersecurity-core/clients/web-admin-minimal/main.js
 * Industrial-grade minimal admin client for cybersecurity-core.
 * - Vanilla ES module, no dependencies.
 * - Secure HTTP client: Bearer JWT, optional HMAC body signature, request timeout,
 *   retries with exponential backoff + jitter, correlation header, RFC 7807 handling.
 * - Session-scoped token storage, JWT decode, expiry checks and warnings.
 * - Safe DOM rendering (no innerHTML), centralized sanitizer for dynamic text.
 * - Example actions: health, metrics, crypto/random, crypto/hash.
 */

"use strict";

// -----------------------------
// Configuration
// -----------------------------
const CONFIG = Object.freeze({
  API_BASE: "", // same-origin by default; set to e.g. "https://api.example.com"
  TIMEOUT_MS: 8000,
  RETRY: Object.freeze({
    maxAttempts: 3,
    backoffBaseMs: 300,
    backoffFactor: 2.0,
    maxBackoffMs: 4000,
    jitter: 0.6, // 0..1
    retryStatus: new Set([502, 503, 504]),
  }),
  CORRELATION_HEADER: "X-Request-ID",
  HMAC_HEADER: "X-Signature", // server accepts base64 or sha256=<hex>
  TOKEN_STORAGE_KEY: "cyber_admin_token",
  SIGNING_SECRET_SESSION_KEY: "cyber_admin_signing_secret_b64", // optional, not persisted unless you choose
});

// -----------------------------
// Utilities
// -----------------------------
const $ = (sel) => /** @type {HTMLElement} */ (document.querySelector(sel));
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

function safeText(node, text) {
  node.textContent = text ?? "";
}

function appendCodeBlock(container, label, value) {
  const wrap = document.createElement("div");
  const h = document.createElement("div");
  const pre = document.createElement("pre");
  h.className = "muted";
  safeText(h, label);
  pre.className = "code";
  safeText(pre, typeof value === "string" ? value : JSON.stringify(value, null, 2));
  wrap.appendChild(h);
  wrap.appendChild(pre);
  container.appendChild(wrap);
}

function nowEpochSec() {
  return Math.floor(Date.now() / 1000);
}

function randomId() {
  if (crypto.randomUUID) return crypto.randomUUID();
  const a = new Uint8Array(16);
  crypto.getRandomValues(a);
  return [...a].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function b64encodeBytes(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function b64decodeToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function parseJwt(token) {
  try {
    const [h, p] = token.split(".").slice(0, 2);
    const pad = (s) => s + "===".slice((s.length + 3) % 4);
    const header = JSON.parse(new TextDecoder().decode(b64decodeToBytes(pad(h.replace(/-/g, "+").replace(/_/g, "/")))));
    const payload = JSON.parse(new TextDecoder().decode(b64decodeToBytes(pad(p.replace(/-/g, "+").replace(/_/g, "/")))));
    return { header, payload };
  } catch {
    return null;
  }
}

function msSleep(ms) {
  return new Promise((res) => setTimeout(res, Math.max(0, ms)));
}

function computeBackoffMs(attemptIndex) {
  const { backoffBaseMs, backoffFactor, maxBackoffMs, jitter } = CONFIG.RETRY;
  const exp = Math.min(maxBackoffMs, backoffBaseMs * Math.pow(backoffFactor, Math.max(0, attemptIndex - 1)));
  const j = Math.random() * (exp * Math.max(0, Math.min(1, jitter)));
  return Math.max(0, exp * (1 - jitter) + j);
}

// -----------------------------
// Token & signing secret store
// -----------------------------
const TokenStore = (() => {
  function get() {
    const v = sessionStorage.getItem(CONFIG.TOKEN_STORAGE_KEY);
    return v || null;
  }
  function set(token) {
    if (!token) {
      sessionStorage.removeItem(CONFIG.TOKEN_STORAGE_KEY);
      return;
    }
    sessionStorage.setItem(CONFIG.TOKEN_STORAGE_KEY, token);
  }
  function clear() {
    sessionStorage.removeItem(CONFIG.TOKEN_STORAGE_KEY);
  }
  function decode() {
    const t = get();
    return t ? parseJwt(t) : null;
  }
  function isNearExpiry(leewaySec = 60) {
    const d = decode();
    if (!d || !d.payload?.exp) return false;
    return d.payload.exp - nowEpochSec() <= leewaySec;
  }
  return { get, set, clear, decode, isNearExpiry };
})();

const SigningSecret = (() => {
  // Optional HMAC signing secret for requests; NOT persisted by default.
  let secretB64 = null;
  async function importKey() {
    if (!secretB64) return null;
    try {
      const raw = b64decodeToBytes(secretB64);
      return await crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    } catch {
      return null;
    }
  }
  async function signBody(bodyBytes) {
    const key = await importKey();
    if (!key) return null;
    const sig = await crypto.subtle.sign("HMAC", key, bodyBytes);
    // Server accepts base64 or "sha256=<hex>"; we send base64.
    return b64encodeBytes(sig);
  }
  function set(b64) {
    secretB64 = b64 || null;
  }
  function get() {
    return secretB64;
  }
  return { importKey, signBody, set, get };
})();

// -----------------------------
// HTTP client
// -----------------------------
class HttpError extends Error {
  constructor(message, status, problem) {
    super(message);
    this.name = "HttpError";
    this.status = status;
    this.problem = problem || null; // RFC 7807 object
  }
}

/**
 * Fetch JSON with security features.
 * @param {string} method
 * @param {string} path
 * @param {{body?: any, headers?: Record<string,string>, idempotent?: boolean}} opts
 */
async function fetchJson(method, path, opts = {}) {
  const url = (CONFIG.API_BASE || "") + path;
  const attempts = Math.max(1, CONFIG.RETRY.maxAttempts);
  const idempotent = opts.idempotent ?? ["GET", "HEAD"].includes(method.toUpperCase());
  /** @type {Uint8Array|null} */
  let bodyBytes = null;
  let body = opts.body;

  if (body && typeof body !== "string" && !(body instanceof ArrayBuffer) && !(body instanceof Uint8Array) && !(body instanceof Blob)) {
    const s = JSON.stringify(body);
    bodyBytes = new TextEncoder().encode(s);
    body = s;
  } else if (typeof body === "string") {
    bodyBytes = new TextEncoder().encode(body);
  } else if (body instanceof Uint8Array) {
    bodyBytes = body;
  } else if (body instanceof ArrayBuffer) {
    bodyBytes = new Uint8Array(body);
  }

  const headers = {
    "Accept": "application/json, application/problem+json",
    ...(bodyBytes ? { "Content-Type": "application/json" } : {}),
    [CONFIG.CORRELATION_HEADER]: randomId(),
    ...opts.headers,
  };

  const token = TokenStore.get();
  if (token) headers["Authorization"] = `Bearer ${token}`;
  if (bodyBytes) {
    const sigB64 = await SigningSecret.signBody(bodyBytes).catch(() => null);
    if (sigB64) headers[CONFIG.HMAC_HEADER] = sigB64;
  }

  let lastErr = null;

  for (let attempt = 1; attempt <= attempts; attempt++) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), CONFIG.TIMEOUT_MS);
    try {
      const res = await fetch(url, {
        method,
        headers,
        body: bodyBytes ? bodyBytes : body ?? undefined,
        signal: ctrl.signal,
        credentials: "same-origin",
      });
      clearTimeout(t);

      const ct = res.headers.get("content-type") || "";
      const isProblem = ct.includes("application/problem+json");
      const isJson = ct.includes("application/json") || isProblem;

      if (!res.ok) {
        let problem = null;
        if (isJson) {
          try {
            problem = await res.json();
          } catch {
            problem = null;
          }
        }
        // 401 -> token invalid, clear it
        if (res.status === 401) {
          TokenStore.clear();
        }

        // Retry if idempotent and status retryable
        if (idempotent && CONFIG.RETRY.retryStatus.has(res.status) && attempt < attempts) {
          await msSleep(computeBackoffMs(attempt));
          continue;
        }

        const msg = problem?.detail || `HTTP ${res.status}`;
        throw new HttpError(msg, res.status, problem);
      }

      // 204 No Content
      if (res.status === 204) return null;

      if (isJson) {
        return await res.json();
      }

      // Attempt text fallback
      return await res.text();
    } catch (err) {
      clearTimeout(t);
      lastErr = err;

      // AbortError or network -> retry if idempotent
      const canRetry =
        idempotent &&
        (err?.name === "AbortError" ||
          err?.name === "TypeError" ||
          err?.message?.includes("NetworkError") ||
          err?.message?.includes("Failed to fetch"));

      if (canRetry && attempt < attempts) {
        await msSleep(computeBackoffMs(attempt));
        continue;
      }

      if (err instanceof HttpError) throw err;
      throw new HttpError(err?.message || "Network error", 0, null);
    }
  }

  // Should not reach here
  throw lastErr || new HttpError("Unknown error", 0, null);
}

// -----------------------------
// UI: wiring and actions
// -----------------------------
const UI = (() => {
  const els = {
    tokenInput: $("#token-input"),
    tokenSaveBtn: $("#token-save"),
    tokenClearBtn: $("#token-clear"),
    tokenInfo: $("#token-info"),
    tokenWarn: $("#token-warn"),
    signingSecretInput: $("#signing-secret-input"),
    signingSecretApplyBtn: $("#signing-secret-apply"),
    out: $("#output"),
    healthBtn: $("#btn-health"),
    metricsBtn: $("#btn-metrics"),
    randomBtn: $("#btn-random"),
    hashForm: $("#form-hash"),
    hashAlgo: $("#hash-algo"),
    hashText: $("#hash-text"),
    busy: $("#busy"),
  };

  function setBusy(v) {
    if (!els.busy) return;
    els.busy.style.visibility = v ? "visible" : "hidden";
  }

  function clearOutput() {
    if (!els.out) return;
    els.out.replaceChildren();
  }

  function printSection(label, data) {
    if (!els.out) return;
    appendCodeBlock(els.out, label, data);
  }

  function renderTokenInfo() {
    if (!els.tokenInfo || !els.tokenWarn) return;
    const t = TokenStore.get();
    if (!t) {
      safeText(els.tokenInfo, "Токен не установлен");
      els.tokenWarn.style.display = "none";
      return;
    }
    const info = TokenStore.decode();
    if (!info) {
      safeText(els.tokenInfo, "Некорректный JWT");
      els.tokenWarn.style.display = "none";
      return;
    }
    const exp = info.payload?.exp ? new Date(info.payload.exp * 1000).toISOString() : "n/a";
    const iat = info.payload?.iat ? new Date(info.payload.iat * 1000).toISOString() : "n/a";
    safeText(
      els.tokenInfo,
      `JWT ok. iss=${info.payload?.iss || "?"}; sub=${info.payload?.sub || "?"}; iat=${iat}; exp=${exp}`
    );
    const near = TokenStore.isNearExpiry(90);
    els.tokenWarn.style.display = near ? "block" : "none";
    if (near) safeText(els.tokenWarn, "Внимание: токен скоро истечет (< 90 сек). Обновите его во избежание 401.");
  }

  function wireAuth() {
    if (els.tokenSaveBtn) {
      els.tokenSaveBtn.addEventListener("click", () => {
        const v = String(els.tokenInput?.value || "").trim();
        TokenStore.set(v || null);
        renderTokenInfo();
      });
    }
    if (els.tokenClearBtn) {
      els.tokenClearBtn.addEventListener("click", () => {
        TokenStore.clear();
        renderTokenInfo();
      });
    }
    if (els.signingSecretApplyBtn) {
      els.signingSecretApplyBtn.addEventListener("click", () => {
        const v = String(els.signingSecretInput?.value || "").trim();
        // Do NOT persist by default
        SigningSecret.set(v || null);
        alert(v ? "HMAC секрет применен в памяти" : "HMAC секрет очищен");
      });
    }
    renderTokenInfo();
  }

  function wireActions() {
    if (els.healthBtn) {
      els.healthBtn.addEventListener("click", async () => {
        clearOutput();
        setBusy(true);
        try {
          const data = await fetchJson("GET", "/health", { idempotent: true });
          printSection("GET /health", data ?? { ok: true });
        } catch (e) {
          printSection("Ошибка /health", e.problem || { message: e.message, status: e.status });
        } finally {
          setBusy(false);
        }
      });
    }

    if (els.metricsBtn) {
      els.metricsBtn.addEventListener("click", async () => {
        clearOutput();
        setBusy(true);
        try {
          // Many /metrics endpoints return text/plain
          const res = await fetch((CONFIG.API_BASE || "") + "/metrics", {
            method: "GET",
            headers: { [CONFIG.CORRELATION_HEADER]: randomId(), ...(TokenStore.get() ? { Authorization: `Bearer ${TokenStore.get()}` } : {}) },
            credentials: "same-origin",
          });
          const text = await res.text();
          printSection("GET /metrics", text);
        } catch (e) {
          printSection("Ошибка /metrics", { message: e.message });
        } finally {
          setBusy(false);
        }
      });
    }

    if (els.randomBtn) {
      els.randomBtn.addEventListener("click", async () => {
        clearOutput();
        setBusy(true);
        try {
          const data = await fetchJson("POST", "/api/v1/crypto/random", { body: { length: 32 } });
          printSection("POST /api/v1/crypto/random", data);
        } catch (e) {
          printSection("Ошибка /crypto/random", e.problem || { message: e.message, status: e.status });
        } finally {
          setBusy(false);
        }
      });
    }

    if (els.hashForm) {
      els.hashForm.addEventListener("submit", async (ev) => {
        ev.preventDefault();
        clearOutput();
        setBusy(true);
        try {
          const algo = String(els.hashAlgo?.value || "sha256");
          const text = String(els.hashText?.value || "");
          const data = await fetchJson("POST", "/api/v1/crypto/hash", {
            body: { algorithm: algo, data_text: text, out: "hex" },
          });
          printSection(`POST /api/v1/crypto/hash (${algo})`, data);
        } catch (e) {
          printSection("Ошибка /crypto/hash", e.problem || { message: e.message, status: e.status });
        } finally {
          setBusy(false);
        }
      });
    }
  }

  function bootBanner() {
    const b = $("#boot-banner");
    if (!b) return;
    const cl = TokenStore.get() ? "ok" : "warn";
    b.classList.add(cl);
    safeText(b, TokenStore.get() ? "Готово: токен найден в сессии" : "Внимание: установите токен для защищенных вызовов");
  }

  function init() {
    wireAuth();
    wireActions();
    bootBanner();
    // Periodic token status update
    setInterval(renderTokenInfo, 5000);
  }

  return { init, printSection, clearOutput, setBusy };
})();

// -----------------------------
// Global export for console debugging (optional)
// -----------------------------
window.AdminApp = Object.freeze({
  fetchJson,
  TokenStore,
  SigningSecret,
  CONFIG,
});

// -----------------------------
// Start
// -----------------------------
document.addEventListener("DOMContentLoaded", () => {
  UI.init();
});
