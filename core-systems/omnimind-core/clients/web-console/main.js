/* OmniMind Core — Web Console main.js
 * Назначение: промышленная инициализация клиента (конфиг, логирование, телеметрия,
 * устойчивые HTTP/SSE/WebSocket вызовы, auth, CSRF, минимальный UI bootstrap).
 * Зависимости: только браузерные API.
 * Совместимость: современные браузеры (ES2020+). При необходимости используйте транспиляцию.
 */

/* =========================
 * Утилиты и общие константы
 * ========================= */
"use strict";

/** Версия фронта (подставляется CI/CD, можно переопределить через window.__OMNI_BUILD__) */
const BUILD_INFO = Object.freeze({
  version: (window.__OMNI_BUILD__ && window.__OMNI_BUILD__.version) || "0.0.0",
  commit: (window.__OMNI_BUILD__ && window.__OMNI_BUILD__.commit) || "dev",
  builtAt: (window.__OMNI_BUILD__ && window.__OMNI_BUILD__.builtAt) || new Date().toISOString()
});

/** Случайная задержка для «джиттера» при ретраях */
function jitter(ms) {
  const delta = Math.floor(ms * 0.2);
  return ms + Math.floor(Math.random() * delta) - Math.floor(delta / 2);
}

/** Пауза */
function sleep(ms, signal) {
  return new Promise((resolve, reject) => {
    const t = setTimeout(resolve, ms);
    if (signal) {
      if (signal.aborted) {
        clearTimeout(t);
        return reject(new DOMException("Aborted", "AbortError"));
      }
      signal.addEventListener("abort", () => {
        clearTimeout(t);
        reject(new DOMException("Aborted", "AbortError"));
      }, { once: true });
    }
  });
}

/** Генерация корреляционного ID */
function uuid4() {
  // Простая реализация без crypto.randomUUID для совместимости
  const s = [], hex = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx";
  for (let i = 0; i < hex.length; i++) {
    const c = hex[i];
    if (c === "x" || c === "y") {
      const r = Math.random() * 16 | 0;
      s.push((c === "x" ? r : (r & 0x3 | 0x8)).toString(16));
    } else {
      s.push(c);
    }
  }
  return s.join("");
}

/** Безопасная маскировка PII/секретов в строках (логирование) */
function redact(text) {
  if (!text || typeof text !== "string") return text;
  return text
    // email
    .replace(/([a-z0-9._%+\-]+)@([a-z0-9.\-]+\.[a-z]{2,})/gi, "***@***")
    // телефоны
    .replace(/\+?\d[\d\-\s()]{7,}\d/gi, "***")
    // токены/pat/jwt
    .replace(/\bsk-[A-Za-z0-9]{16,}\b/g, "sk-***")
    .replace(/\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b/g, "jwt***")
    // возможные ключи
    .replace(/("?(token|secret|api[_-]?key|password)"?\s*[:=]\s*")([^"]+)("/gi, '$1***$4');
}

/* ==============
 * Конфиг-лоадер
 * ============== */
/**
 * Загружает конфигурацию:
 * 1) window.__OMNI_CONFIG__ (приоритет)
 * 2) <meta name="omni:config" content='{"apiBase": "..."}'>
 * 3) /config.json (необязательно)
 * 4) значения по умолчанию
 */
async function loadConfig() {
  const defaults = {
    env: "dev",
    apiBase: "/api",
    wsBase: (location.protocol === "https:" ? "wss://" : "ws://") + location.host,
    sseBase: "/api",
    telemetry: { enabled: true, endpoint: "/api/telemetry", sampleRate: 1.0 },
    csrfCookie: "csrf_token",
    storageKeyPrefix: "omni:",
    logLevel: "info",
    features: {}
  };

  if (window.__OMNI_CONFIG__) return { ...defaults, ...window.__OMNI_CONFIG__ };

  const meta = document.querySelector('meta[name="omni:config"]');
  if (meta && meta.content) {
    try {
      const cfg = JSON.parse(meta.content);
      return { ...defaults, ...cfg };
    } catch { /* ignore */ }
  }

  try {
    const resp = await fetch("/config.json", { credentials: "same-origin" });
    if (resp.ok) {
      const cfg = await resp.json();
      return { ...defaults, ...cfg };
    }
  } catch { /* ignore */ }

  return defaults;
}

/* =========
 * Логгер
 * ========= */
class Logger {
  constructor(level = "info") {
    this.levels = { trace: 10, debug: 20, info: 30, warn: 40, error: 50 };
    this.level = this.levels[level] || this.levels.info;
    this.rate = new Map(); // защита от лог-спама: key -> {count, ts}
  }
  should(lvl) { return (this.levels[lvl] || 999) >= this.level; }
  _emit(lvl, msg, ctx) {
    const payload = {
      ts: new Date().toISOString(),
      lvl, msg: typeof msg === "string" ? redact(msg) : msg,
      ctx: ctx ? JSON.parse(JSON.stringify(ctx, (k, v) => typeof v === "string" ? redact(v) : v)) : undefined
    };
    // простая анти-флуд защита
    const key = JSON.stringify({ msg: payload.msg, lvl });
    const e = this.rate.get(key) || { count: 0, ts: Date.now() };
    if (Date.now() - e.ts < 1000 && e.count > 20) return; // не чаще 20/сек одинаковых
    e.count += 1; this.rate.set(key, e);
    // вывод
    const line = JSON.stringify(payload);
    if (lvl === "error") console.error(line); else if (lvl === "warn") console.warn(line); else console.log(line);
  }
  trace(m, c) { if (this.should("trace")) this._emit("trace", m, c); }
  debug(m, c) { if (this.should("debug")) this._emit("debug", m, c); }
  info(m, c)  { if (this.should("info"))  this._emit("info", m, c); }
  warn(m, c)  { if (this.should("warn"))  this._emit("warn", m, c); }
  error(m, c) { if (this.should("error")) this._emit("error", m, c); }
}

/* ============
 * Телеметрия
 * ============ */
class Telemetry {
  constructor(cfg, logger) {
    this.enabled = !!(cfg.telemetry && cfg.telemetry.enabled);
    this.endpoint = cfg.telemetry?.endpoint || "/api/telemetry";
    this.sampleRate = Number(cfg.telemetry?.sampleRate ?? 1.0);
    this.common = {
      service: "omnimind-web-console",
      env: cfg.env,
      version: BUILD_INFO.version
    };
    this.log = logger;
    this.buffer = [];
    this.flushInterval = 5000;
    if (this.enabled) this._startFlushLoop();
  }
  _sampled() { return Math.random() < this.sampleRate; }
  counter(name, value = 1, labels = {}) {
    if (!this.enabled || !this._sampled()) return;
    this.buffer.push({ type: "counter", name, value, labels: { ...this.common, ...labels }, t: Date.now() });
  }
  histogram(name, value, labels = {}) {
    if (!this.enabled || !this._sampled()) return;
    this.buffer.push({ type: "histogram", name, value, labels: { ...this.common, ...labels }, t: Date.now() });
  }
  event(name, fields = {}) {
    if (!this.enabled || !this._sampled()) return;
    this.buffer.push({ type: "event", name, fields: { ...this.common, ...fields }, t: Date.now() });
  }
  trace(span, fields = {}) {
    if (!this.enabled || !this._sampled()) return;
    this.buffer.push({ type: "trace", span, fields: { ...this.common, ...fields }, t: Date.now() });
  }
  flushSync() {
    if (!this.enabled || this.buffer.length === 0) return;
    const payload = JSON.stringify(this.buffer.splice(0, this.buffer.length));
    try { navigator.sendBeacon(this.endpoint, payload); } catch {
      // sendBeacon может не сработать; откатываемся на fetch без ожидания
      fetch(this.endpoint, { method: "POST", headers: { "content-type": "application/json" }, body: payload, keepalive: true }).catch(() => {});
    }
  }
  _startFlushLoop() {
    const loop = async () => {
      while (true) {
        await sleep(this.flushInterval);
        try { this.flushSync(); } catch (e) { this.log.warn("telemetry flush failed", { e: String(e) }); }
      }
    };
    loop();
    // на закрытие вкладки — вынужденный flush
    window.addEventListener("visibilitychange", () => { if (document.visibilityState === "hidden") this.flushSync(); });
    window.addEventListener("pagehide", () => this.flushSync());
    window.addEventListener("beforeunload", () => this.flushSync());
  }
}

/* ===========
 * Хранилище
 * =========== */
class Storage {
  constructor(prefix) { this.prefix = prefix || "omni:"; }
  get(key, defVal = null) { try { const v = localStorage.getItem(this.prefix + key); return v ? JSON.parse(v) : defVal; } catch { return defVal; } }
  set(key, val) { try { localStorage.setItem(this.prefix + key, JSON.stringify(val)); } catch { /* ignore */ } }
  del(key) { try { localStorage.removeItem(this.prefix + key); } catch { /* ignore */ } }
}

/* ========
 * Auth
 * ======== */
class Auth {
  constructor(store, logger) {
    this.store = store;
    this.log = logger;
  }
  get token() { return this.store.get("token"); }
  set token(v) { this.store.set("token", v); }
  get refreshToken() { return this.store.get("refresh"); }
  set refreshToken(v) { this.store.set("refresh", v); }
  clear() { this.store.del("token"); this.store.del("refresh"); }
}

/* ==========
 * CSRF util
 * ========== */
function getCookie(name) {
  const m = document.cookie.match(new RegExp("(^|;)\\s*" + name + "\\s*=\\s*([^;]+)"));
  return m ? decodeURIComponent(m.pop()) : null;
}

/* ===============
 * HTTP-клиент
 * =============== */
/**
 * Надежный fetch с:
 * - таймаутом через AbortController
 * - до 5 ретраев с экспоненциальной паузой и джиттером на 5xx/сетевые
 * - автоматическим добавлением auth/CSRF заголовков
 * - авто-refresh токена при 401 (одна попытка)
 */
class ApiClient {
  constructor(cfg, auth, logger, telemetry) {
    this.cfg = cfg;
    this.base = cfg.apiBase.replace(/\/+$/, "");
    this.log = logger;
    this.auth = auth;
    this.tm = telemetry;
    this.defaultTimeout = 15000;
    this.maxRetries = 5;
  }

  _headers(extra = {}) {
    const h = { "accept": "application/json", ...extra };
    if (this.auth.token) h["authorization"] = "Bearer " + this.auth.token;
    const csrf = getCookie(this.cfg.csrfCookie);
    if (csrf) h["x-csrf-token"] = csrf;
    return h;
  }

  async _doFetch(path, opts = {}, attempt = 0, refreshed = false) {
    const url = path.startsWith("http") ? path : this.base + path;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), opts.timeout || this.defaultTimeout);
    const start = performance.now();
    const requestId = uuid4();

    try {
      const resp = await fetch(url, {
        method: opts.method || "GET",
        headers: this._headers(opts.headers || {}),
        body: opts.body,
        credentials: "same-origin",
        signal: controller.signal,
        mode: "cors",
        cache: "no-store",
        keepalive: opts.keepalive || false
      });

      const dt = (performance.now() - start) / 1000;
      this.tm.histogram("http.client.duration", dt, { path, method: opts.method || "GET", code: String(resp.status) });

      // попытка refresh токена на 401
      if (resp.status === 401 && !refreshed && this.auth.refreshToken) {
        try {
          await this.refresh();
          return this._doFetch(path, opts, attempt, true);
        } catch (e) {
          this.log.warn("token refresh failed", { e: String(e) });
        }
      }

      if (!resp.ok && [502, 503, 504].includes(resp.status) && attempt < this.maxRetries) {
        const backoff = jitter(Math.min(1000 * Math.pow(2, attempt), 10000));
        this.tm.counter("http.client.retry", 1, { path, code: String(resp.status), attempt: String(attempt + 1) });
        await sleep(backoff);
        return this._doFetch(path, opts, attempt + 1, refreshed);
      }

      return resp;
    } catch (err) {
      const isAbort = err && String(err.name || "").includes("Abort");
      if (!isAbort && attempt < this.maxRetries) {
        const backoff = jitter(Math.min(1000 * Math.pow(2, attempt), 10000));
        this.tm.counter("http.client.error.retry", 1, { path, attempt: String(attempt + 1) });
        await sleep(backoff);
        return this._doFetch(path, opts, attempt + 1, refreshed);
      }
      this.tm.counter("http.client.error", 1, { path });
      throw err;
    } finally {
      clearTimeout(timeout);
    }
  }

  async json(path, opts = {}) {
    const resp = await this._doFetch(path, { ...opts, headers: { "content-type": "application/json", ...(opts.headers || {}) }, body: opts.body && typeof opts.body !== "string" ? JSON.stringify(opts.body) : opts.body });
    const text = await resp.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch { /* текстовая ошибка */ }
    if (!resp.ok) {
      const err = new Error(`HTTP ${resp.status} ${resp.statusText}`);
      err.status = resp.status; err.body = data || text;
      throw err;
    }
    return data;
  }

  async refresh() {
    const token = this.auth.refreshToken;
    if (!token) throw new Error("no refresh token");
    const r = await this.json("/auth/refresh", { method: "POST", body: { refresh_token: token } });
    if (!r || !r.access_token) throw new Error("refresh failed");
    this.auth.token = r.access_token;
    if (r.refresh_token) this.auth.refreshToken = r.refresh_token;
    this.tm.event("auth.refresh.ok");
  }
}

/* ==================
 * SSE-клиент (EventSource)
 * ================== */
class SSEClient {
  constructor(cfg, logger, telemetry) {
    this.cfg = cfg; this.log = logger; this.tm = telemetry;
  }
  /**
   * Подписка на SSE:
   * onMessage: ({event, id, data}) => void
   * options: { path, query, lastEventId, headers }
   */
  subscribe({ path, query = {}, lastEventId = null, headers = {} }, onMessage) {
    const url = new URL((path.startsWith("http") ? path : (this.cfg.sseBase.replace(/\/+$/, "") + path)), location.href);
    Object.entries(query || {}).forEach(([k, v]) => { if (v != null) url.searchParams.set(k, String(v)); });
    const es = new EventSource(url.toString(), { withCredentials: true });
    let openedAt = Date.now();

    const onopen = () => {
      this.tm.event("sse.open", { path });
      this.log.info("sse open", { path });
    };
    const onerror = (e) => {
      this.tm.event("sse.error", { path });
      this.log.warn("sse error", { path, e: String(e) });
      // Браузер сам переподключится; фиксируем метрику длительности
      this.tm.histogram("sse.session.seconds", (Date.now() - openedAt) / 1000, { path });
      openedAt = Date.now();
    };
    const onmessage = (ev) => {
      const payload = { event: ev.type || "message", id: ev.lastEventId || null, data: ev.data };
      try { onMessage(payload); } catch (e) { this.log.warn("sse handler error", { e: String(e) }); }
    };

    es.addEventListener("open", onopen);
    es.addEventListener("error", onerror);
    es.addEventListener("message", onmessage);
    if (lastEventId) try { es.lastEventId = lastEventId; } catch { /* ignore */ }

    return {
      close: () => {
        try { es.close(); } catch { /* ignore */ }
        this.tm.histogram("sse.session.seconds", (Date.now() - openedAt) / 1000, { path });
      }
    };
  }
}

/* ====================
 * WebSocket-менеджер
 * ==================== */
class WebSocketManager {
  constructor(cfg, logger, telemetry) {
    this.cfg = cfg; this.log = logger; this.tm = telemetry;
    this.sockets = new Map(); // key -> {ws, url, protocols, backoff, timers}
  }
  connect(key, path, { protocols = [], params = {} } = {}) {
    const url = new URL((path.startsWith("ws") ? path : (this.cfg.wsBase.replace(/\/+$/, "") + path)));
    Object.entries(params || {}).forEach(([k, v]) => { if (v != null) url.searchParams.set(k, String(v)); });

    const state = { ws: null, url: url.toString(), protocols, backoff: 500, hb: null, closedByUser: false };
    const open = () => {
      const ws = new WebSocket(state.url, protocols);
      state.ws = ws;
      ws.onopen = () => {
        this.log.info("ws open", { key, url: state.url });
        this.tm.event("ws.open", { key });
        state.backoff = 500;
        // heartbeat
        state.hb = setInterval(() => { try { ws.send(JSON.stringify({ t: "ping", ts: Date.now() })); } catch { /* ignore */ } }, 15000);
      };
      ws.onmessage = (ev) => {
        let data = null;
        try { data = JSON.parse(ev.data); } catch { data = { t: "text", data: String(ev.data || "") }; }
        if (data && data.t === "pong") return; // heartbeat
        document.dispatchEvent(new CustomEvent(`ws:${key}:message`, { detail: data }));
      };
      ws.onclose = () => {
        clearInterval(state.hb); state.hb = null;
        this.tm.event("ws.close", { key });
        if (!state.closedByUser) { // авто-reconnect
          const backoff = jitter(Math.min(state.backoff *= 2, 10000));
          setTimeout(open, backoff);
        }
      };
      ws.onerror = (e) => { this.log.warn("ws error", { key, e: String(e) }); };
    };
    open();
    this.sockets.set(key, state);
    return {
      send: (obj) => { try { state.ws && state.ws.readyState === 1 && state.ws.send(JSON.stringify(obj)); } catch { /* ignore */ } },
      close: () => { state.closedByUser = true; clearInterval(state.hb); try { state.ws && state.ws.close(); } catch { /* ignore */ } this.sockets.delete(key); }
    };
  }
}

/* ==========================
 * Минимальный UI bootstrap
 * ========================== */
function sanitizeHTML(str) {
  const div = document.createElement("div");
  div.textContent = String(str ?? "");
  return div.innerHTML;
}

function mountUI({ logger, telemetry, api }) {
  const root = document.getElementById("app");
  if (!root) {
    logger.warn("root #app not found — UI mount skipped");
    return;
  }
  root.innerHTML = `
    <section id="header" class="omni-header">
      <div class="brand">OmniMind Web Console</div>
      <div class="meta">v${sanitizeHTML(BUILD_INFO.version)} • ${sanitizeHTML(BUILD_INFO.commit)}</div>
    </section>
    <section class="controls">
      <form id="loginForm">
        <input id="loginUser" placeholder="username" autocomplete="username" />
        <input id="loginPass" placeholder="password" type="password" autocomplete="current-password" />
        <button id="btnLogin" type="submit">Login</button>
      </form>
      <button id="btnPing">Ping API</button>
      <button id="btnStream">Start Stream</button>
      <button id="btnStop">Stop Stream</button>
    </section>
    <section id="output" class="output"></section>
  `;

  const out = document.getElementById("output");
  function write(line, kind = "info") {
    const el = document.createElement("div");
    el.className = `line ${kind}`;
    el.textContent = `[${new Date().toLocaleTimeString()}] ${line}`;
    out.appendChild(el);
    out.scrollTop = out.scrollHeight;
  }

  // Login
  const loginForm = document.getElementById("loginForm");
  loginForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const uname = document.getElementById("loginUser").value;
    const pass = document.getElementById("loginPass").value;
    try {
      const resp = await api.json("/auth/login", { method: "POST", body: { username: uname, password: pass } });
      window.__OMNI_AUTH__.token = resp.access_token;
      if (resp.refresh_token) window.__OMNI_AUTH__.refreshToken = resp.refresh_token;
      telemetry.event("login.ok", { user: "masked" });
      write("Login OK");
    } catch (err) {
      write(`Login failed: ${String(err && err.message || err)}`, "error");
    }
  });

  // Ping
  document.getElementById("btnPing").addEventListener("click", async () => {
    try {
      const r = await api.json("/healthz");
      write(`Ping: ${JSON.stringify(r)}`);
    } catch (e) {
      write(`Ping error: ${String(e && e.message || e)}`, "error");
    }
  });

  // Streaming (SSE demo)
  let sub = null;
  document.getElementById("btnStream").addEventListener("click", () => {
    if (sub) return;
    sub = window.__OMNI_SSE__.subscribe({ path: "/stream/logs", query: { tail: 10 } }, (m) => {
      write(`SSE ${m.event}: ${m.data}`);
    });
  });
  document.getElementById("btnStop").addEventListener("click", () => {
    if (sub) { sub.close(); sub = null; write("SSE stopped"); }
  });
}

/* ===========================
 * Глобальные обработчики ошибок
 * =========================== */
function installGlobalErrorHandlers(logger, telemetry) {
  window.addEventListener("error", (e) => {
    logger.error("window.error", { msg: String(e.message || ""), src: e.filename, ln: e.lineno, col: e.colno });
    telemetry.event("js.error", { type: "error", message: String(e.message || "") });
  });
  window.addEventListener("unhandledrejection", (e) => {
    logger.error("unhandledrejection", { reason: String(e.reason && e.reason.message || e.reason || "") });
    telemetry.event("js.error", { type: "unhandledrejection", message: String(e.reason && e.reason.message || e.reason || "") });
  });
}

/* ===========
 * Инициализация
 * =========== */
async function init() {
  const cfg = await loadConfig();
  const logger = new Logger(cfg.logLevel);
  const telemetry = new Telemetry(cfg, logger);
  const storage = new Storage(cfg.storageKeyPrefix);
  const auth = new Auth(storage, logger);
  const api = new ApiClient(cfg, auth, logger, telemetry);
  const sse = new SSEClient(cfg, logger, telemetry);
  const ws = new WebSocketManager(cfg, logger, telemetry);

  installGlobalErrorHandlers(logger, telemetry);

  // Экспорт для других скриптов/отладки
  window.OmniConsole = Object.freeze({
    cfg, logger, telemetry, storage, auth, api, sse, ws, build: BUILD_INFO
  });
  window.__OMNI_AUTH__ = auth;
  window.__OMNI_API__ = api;
  window.__OMNI_SSE__ = sse;
  window.__OMNI_WS__ = ws;

  // Телеметрия по загрузке
  telemetry.event("app.start", { version: BUILD_INFO.version, commit: BUILD_INFO.commit });

  // Монтируем простой UI, если есть #app
  mountUI({ logger, telemetry, api });

  logger.info("OmniMind Web Console initialized", { version: BUILD_INFO.version, commit: BUILD_INFO.commit });
}

// Автозапуск
init().catch(err => {
  // Если инициализация упала — хотя бы лог в консоль
  console.error(JSON.stringify({ ts: new Date().toISOString(), lvl: "error", msg: "init failed", err: String(err && err.message || err) }));
});

/* =======================
 * Экспорт для unit-тестов
 * ======================= */
export {
  loadConfig,
  Logger,
  Telemetry,
  Storage,
  Auth,
  ApiClient,
  SSEClient,
  WebSocketManager,
  redact,
  uuid4,
  jitter,
  sleep
};
