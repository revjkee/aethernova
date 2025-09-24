/* eslint-disable no-console */
"use strict";

/**
 * Zero Trust Core — Web Admin (minimal)
 * Производственный main.js без внешних зависимостей:
 * - Строгая CSP-совместимость (без eval/inline), поддержка nonce для инжекта <style>
 * - Безопасный DOM (textContent/attr, ограниченная санитизация)
 * - WebCrypto (ECDSA P-256) для PoP-аттестации сессии
 * - HTTP клиент с таймаутом, повторами, backoff, CSRF, ETag, correlation-id
 * - Ин-мемори хранение токена (fallback sessionStorage), постMessage с проверкой origin
 * - SPA-роутинг (hash) + базовые экраны: Dashboard, Sessions, Policies, Audit
 * - Телеметрия (минимальная): page_view, action_click, http_error (batched)
 * - Офлайн/онлайн индикатор, защита от бурста кликов, защита от XSS
 */

/* =========================
 *  CONFIG & CONSTANTS
 * ========================= */
const CONFIG = (() => {
  // Порядок приоритета: window.__ZTC_CONFIG -> <meta name="ztc-config"> -> дефолт
  const meta = document.querySelector('meta[name="ztc-config"]');
  let metaCfg = {};
  try { metaCfg = meta ? JSON.parse(meta.getAttribute("content") || "{}") : {}; } catch (_) {}
  const winCfg = (typeof window !== "undefined" && window.__ZTC_CONFIG) ? window.__ZTC_CONFIG : {};
  const env = {
    apiBase: "/api",
    telemetryBase: "/telemetry",
    service: "zero-trust-core",
    version: "1.0.0",
    env: "dev",
    region: "unknown",
    allowedOrigins: [], // список допустимых origin для postMessage
    nonce: (document.currentScript && document.currentScript.nonce) || "",
    requestTimeoutMs: 8000,
    retryCount: 2,
    retryBaseMs: 200,
    csrfCookie: "csrf_token",
    routes: {
      sessionInit: "/v1/session/init",
      sessionAttest: "/v1/session/attest",
      me: "/v1/me",
      sessions: "/v1/sessions",
      policies: "/v1/policies",
      audit: "/v1/audit",
    },
  };
  return Object.freeze({ ...env, ...metaCfg, ...winCfg });
})();

/* =========================
 *  UTILITIES (SAFE DOM, ID, COOKIES)
 * ========================= */
const SafeDOM = (() => {
  function text(el, value) { if (el) el.textContent = String(value ?? ""); }
  function clear(el) { if (el) while (el.firstChild) el.removeChild(el.firstChild); }
  function el(name, attrs = {}, children = []) {
    const node = document.createElement(name);
    for (const [k, v] of Object.entries(attrs)) {
      // Только безопасные атрибуты
      if (k === "class") node.className = String(v);
      else if (k === "id") node.id = String(v);
      else if (k.startsWith("data-")) node.setAttribute(k, String(v));
      else if (k === "href" || k === "src") {
        const url = sanitizeURL(String(v));
        if (url) node.setAttribute(k, url);
      } else if (k === "role" || k === "aria-label" || k === "title") {
        node.setAttribute(k, String(v));
      }
    }
    for (const ch of [].concat(children)) {
      if (typeof ch === "string" || typeof ch === "number") {
        node.appendChild(document.createTextNode(String(ch)));
      } else if (ch instanceof Node) {
        node.appendChild(ch);
      }
    }
    return node;
  }
  function sanitizeURL(url) {
    try {
      const u = new URL(url, location.origin);
      // Запрещаем javascript: и data: для ссылок
      if (["http:", "https:"].includes(u.protocol)) return u.href;
      if (u.origin === location.origin) return u.href;
      return "";
    } catch { return ""; }
  }
  function getCookie(name) {
    const m = document.cookie.match(new RegExp("(^| )" + name + "=([^;]+)"));
    return m ? decodeURIComponent(m[2]) : "";
  }
  function once(fn) {
    let called = false;
    return function(...args) {
      if (called) return;
      called = true;
      return fn.apply(this, args);
    };
  }
  function throttle(fn, ms) {
    let last = 0;
    let t;
    return function(...args) {
      const now = Date.now();
      if (now - last >= ms) {
        last = now;
        fn.apply(this, args);
      } else {
        clearTimeout(t);
        t = setTimeout(() => {
          last = Date.now();
          fn.apply(this, args);
        }, ms - (now - last));
      }
    };
  }
  // CSS инжект (CSP nonce‑friendly)
  function injectStyle(css) {
    const style = document.createElement("style");
    if (CONFIG.nonce) style.setAttribute("nonce", CONFIG.nonce);
    style.appendChild(document.createTextNode(css));
    document.head.appendChild(style);
  }
  return { text, clear, el, sanitizeURL, getCookie, once, throttle, injectStyle };
})();

/* =========================
 *  CRYPTO (ECDSA P-256 PoP)
 * ========================= */
const CryptoPoP = (() => {
  const ALG = { name: "ECDSA", namedCurve: "P-256" };
  const SIGN = { name: "ECDSA", hash: { name: "SHA-256" } };

  async function ensureKeyPair() {
    // Храним CryptoKey в памяти; pub JWK — в sessionStorage (безопасно для восстановления между обновлениями вкладки)
    if (App.state.keys.privateKey && App.state.keys.publicKey) return App.state.keys;
    const kp = await crypto.subtle.generateKey(ALG, true, ["sign", "verify"]);
    App.state.keys.privateKey = kp.privateKey;
    App.state.keys.publicKey  = kp.publicKey;
    const jwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
    sessionStorage.setItem("ztc_pub_jwk", JSON.stringify(jwk));
    return App.state.keys;
  }

  async function sign(data) {
    const enc = new TextEncoder();
    const sig = await crypto.subtle.sign(SIGN, App.state.keys.privateKey, enc.encode(data));
    return b64url(sig);
  }

  async function digestPII(value) {
    const enc = new TextEncoder();
    const d = await crypto.subtle.digest("SHA-256", enc.encode(String(value || "")));
    return hex(d);
  }

  function b64url(buf) {
    const b = arrayBufferToBase64(buf)
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    return b;
  }
  function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let s = "";
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }
  function hex(buf) {
    const b = new Uint8Array(buf);
    return [...b].map(x => x.toString(16).padStart(2, "0")).join("");
  }

  return { ensureKeyPair, sign, digestPII };
})();

/* =========================
 *  TELEMETRY (BATCH)
 * ========================= */
const Telemetry = (() => {
  const q = [];
  let flushTimer = null;
  const FLUSH_MS = 3000;
  const MAX_BATCH = 20;

  function push(ev) {
    try {
      q.push({
        ts: Date.now(),
        service: CONFIG.service,
        version: CONFIG.version,
        env: CONFIG.env,
        region: CONFIG.region,
        trace: App.state.traceId,
        ...ev
      });
      if (q.length >= MAX_BATCH) flush();
      else if (!flushTimer) flushTimer = setTimeout(flush, FLUSH_MS);
    } catch {}
  }

  async function flush() {
    clearTimeout(flushTimer); flushTimer = null;
    if (!q.length) return;
    const batch = q.splice(0, MAX_BATCH);
    try {
      await fetch(`${CONFIG.telemetryBase}/events`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-correlation-id": App.state.correlationId
        },
        body: JSON.stringify(batch),
        keepalive: true
      });
    } catch {}
  }

  window.addEventListener("beforeunload", () => { try { navigator.sendBeacon?.(`${CONFIG.telemetryBase}/events`, JSON.stringify(q)); } catch {} });

  return { push, flush };
})();

/* =========================
 *  HTTP CLIENT
 * ========================= */
const Http = (() => {
  function correlation() {
    // Простой ULID-подобный id
    const r = crypto.getRandomValues(new Uint8Array(8));
    return `${Date.now().toString(36)}-${[...r].map(x => x.toString(16).padStart(2,"0")).join("")}`;
  }
  async function request(path, { method = "GET", headers = {}, body, timeoutMs = CONFIG.requestTimeoutMs, retries = CONFIG.retryCount, etagCacheKey } = {}) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeoutMs);
    const url = new URL(path.startsWith("http") ? path : CONFIG.apiBase + path, location.origin);
    const h = {
      "accept": "application/json",
      "x-correlation-id": App.state.correlationId,
      "x-trace-id": App.state.traceId,
      "x-request-ts": String(Date.now()),
      ...headers
    };
    // CSRF
    const csrf = SafeDOM.getCookie(CONFIG.csrfCookie);
    if (csrf) h["x-csrf-token"] = csrf;
    // Bearer (in‑memory; fallback sessionStorage)
    const token = App.state.token || sessionStorage.getItem("ztc_token") || "";
    if (token) h["authorization"] = `Bearer ${token}`;
    // ETag cache
    if (etagCacheKey && App.state.etags[etagCacheKey]) h["if-none-match"] = App.state.etags[etagCacheKey];
    // X-Signature (HMAC‑like через ECDSA PoP челлендж недоступен синхронно; здесь добавим public key fingerprint)
    const pubJwk = sessionStorage.getItem("ztc_pub_jwk");
    if (pubJwk) { h["x-pop-pubjwk-sha256"] = await CryptoPoP.digestPII(pubJwk); }

    const opts = { method, headers: h, signal: ctrl.signal };
    if (body) {
      opts.body = (typeof body === "string") ? body : JSON.stringify(body);
      if (!h["content-type"]) h["content-type"] = "application/json";
    }

    let attempt = 0;
    let lastErr;
    while (attempt <= retries) {
      try {
        const res = await fetch(url.href, opts);
        clearTimeout(t);
        const etag = res.headers.get("etag");
        if (etag && etagCacheKey) App.state.etags[etagCacheKey] = etag;

        if (res.status === 401) { App.actions.handleUnauth(); throw new Error("unauthorized"); }
        if (res.status === 204) return { ok: true, status: 204, data: null };
        if (res.status === 304 && etagCacheKey && App.state.cache[etagCacheKey]) return { ok: true, status: 304, data: App.state.cache[etagCacheKey] };

        const ct = res.headers.get("content-type") || "";
        const data = ct.includes("application/json") ? await res.json().catch(() => ({})) : await res.text();

        if (!res.ok) {
          if (res.status >= 500 && attempt < retries) {
            await backoff(attempt++); continue;
          }
          Telemetry.push({ type: "http_error", path: url.pathname, status: res.status });
          return { ok: false, status: res.status, data };
        }
        if (etagCacheKey) App.state.cache[etagCacheKey] = data;
        return { ok: true, status: res.status, data };
      } catch (e) {
        lastErr = e;
        if (e.name === "AbortError") {
          if (attempt < retries) { await backoff(attempt++); continue; }
          Telemetry.push({ type: "http_error", path: url.pathname, status: 0, error: "timeout" });
          return { ok: false, status: 0, data: { error: "timeout" } };
        }
        if (attempt < retries) { await backoff(attempt++); continue; }
        Telemetry.push({ type: "http_error", path: url.pathname, status: 0, error: String(e && e.message || "error") });
        return { ok: false, status: 0, data: { error: String(e && e.message || "error") } };
      } finally {
        // не очищаем t здесь, иначе при ретраях сломаем abort; очищаем на успешном теле выше
      }
    }
    throw lastErr;
  }

  async function backoff(attempt) {
    const base = CONFIG.retryBaseMs;
    const jitter = Math.floor(Math.random() * base);
    await new Promise(r => setTimeout(r, Math.min(2000, (2 ** attempt) * base + jitter)));
  }

  return { request, correlation };
})();

/* =========================
 *  STATE & STORE
 * ========================= */
const App = {
  state: {
    token: "",                 // in-memory access token
    keys: { privateKey: null, publicKey: null },
    etags: Object.create(null),
    cache: Object.create(null),
    correlationId: "",
    traceId: "",
    user: null,
    online: navigator.onLine,
  },
  actions: {},
  ui: {},
};

/* =========================
 *  BOOTSTRAP
 * ========================= */
(async function boot() {
  try {
    App.state.correlationId = Http.correlation();
    App.state.traceId = Http.correlation();
    secureStyles();
    bindGlobalHandlers();

    Telemetry.push({ type: "page_view", page: "boot" });

    await CryptoPoP.ensureKeyPair();
    await sessionInitAndAttest();  // PoP

    await Promise.all([
      App.actions.loadUser(),
      App.actions.loadDashboardData()
    ]);

    App.ui.mount();
    Router.init();
  } catch (e) {
    renderFatal(e);
  }
})();

/* =========================
 *  SESSION INIT + ATTEST
 * ========================= */
async function sessionInitAndAttest() {
  // 1) Инициализация: отправляем публичный ключ, получаем challenge
  const pubJwk = sessionStorage.getItem("ztc_pub_jwk");
  const initRes = await Http.request(CONFIG.routes.sessionInit, {
    method: "POST",
    body: { pub_jwk: pubJwk, user_agent: navigator.userAgent.slice(0, 128) }
  });
  if (!initRes.ok) throw new Error("Session init failed");
  const { challenge, token_hint } = initRes.data || {};
  // 2) Подписываем челлендж
  const signature = await CryptoPoP.sign(challenge || `${Date.now()}`);
  const attestRes = await Http.request(CONFIG.routes.sessionAttest, {
    method: "POST",
    body: { challenge, signature }
  });
  if (!attestRes.ok) throw new Error("Session attest failed");
  // 3) Токен (приходит из ответа или postMessage OAuth)
  const { access_token } = attestRes.data || {};
  if (access_token) {
    App.state.token = access_token;
    sessionStorage.setItem("ztc_token", access_token); // допустимый fallback
  } else if (token_hint) {
    // Ждем postMessage (если OAuth редирект инициирован сервером)
    await waitForTokenMessage(token_hint, 5000);
  }
}

function waitForTokenMessage(expectedHint, ms) {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => {
      window.removeEventListener("message", onMsg);
      reject(new Error("Token message timeout"));
    }, ms);

    function onMsg(ev) {
      try {
        if (!isAllowedOrigin(ev.origin)) return;
        const d = ev.data || {};
        if (d.type === "ztc_token" && d.hint === expectedHint && typeof d.token === "string") {
          App.state.token = d.token;
          sessionStorage.setItem("ztc_token", d.token);
          clearTimeout(t);
          window.removeEventListener("message", onMsg);
          resolve(void 0);
        }
      } catch {}
    }
    window.addEventListener("message", onMsg);
  });
}

function isAllowedOrigin(origin) {
  if (!CONFIG.allowedOrigins || !CONFIG.allowedOrigins.length) return origin === location.origin;
  return CONFIG.allowedOrigins.includes(origin);
}

/* =========================
 *  ACTIONS (API LOADERS)
 * ========================= */
App.actions.handleUnauth = function() {
  // Простая реакция: очистка токена и перезагрузка на страницу логина
  App.state.token = "";
  sessionStorage.removeItem("ztc_token");
  location.replace("/login?next=" + encodeURIComponent(location.href));
};

App.actions.loadUser = async function() {
  const res = await Http.request(CONFIG.routes.me, { etagCacheKey: "me" });
  if (res.ok) App.state.user = res.data;
};

App.actions.loadDashboardData = async function() {
  // Здесь можно подгрузить агрегаты для панели (для примера — быстрая проверка доступности)
  await Promise.all([
    Http.request(CONFIG.routes.sessions, { etagCacheKey: "sessions" }),
    Http.request(CONFIG.routes.policies, { etagCacheKey: "policies" }),
    Http.request(CONFIG.routes.audit, { etagCacheKey: "audit" }),
  ]);
};

/* =========================
 *  UI (RENDER)
 * ========================= */
App.ui.mount = function mount() {
  const root = document.getElementById("app") || document.body.appendChild(document.createElement("div"));
  root.id = "app";
  SafeDOM.clear(root);

  // Shell
  const header = SafeDOM.el("header", { class: "ztc-header" }, [
    SafeDOM.el("div", { class: "brand" }, [
      SafeDOM.el("strong", {}, [CONFIG.service]),
      SafeDOM.el("span", { class: "muted" }, [`v${CONFIG.version}`]),
    ]),
    SafeDOM.el("nav", { class: "nav" }, [
      navLink("#/dashboard", "Панель"),
      navLink("#/sessions", "Сессии"),
      navLink("#/policies", "Политики"),
      navLink("#/audit", "Аудит")
    ]),
    SafeDOM.el("div", { class: "status" }, [
      SafeDOM.el("span", { id: "net-status", class: App.state.online ? "ok" : "bad", "aria-label":"network" }, [App.state.online ? "Online" : "Offline"]),
      SafeDOM.el("span", { class: "sep" }, ["•"]),
      SafeDOM.el("span", { id: "user-name" }, [App.state.user && App.state.user.name ? String(App.state.user.name) : "Гость"]),
    ])
  ]);

  const main = SafeDOM.el("main", { id: "view", class: "view" });
  const footer = SafeDOM.el("footer", { class: "ztc-footer" }, [
    SafeDOM.el("span", {}, [`${CONFIG.env}@${CONFIG.region}`])
  ]);

  root.appendChild(header);
  root.appendChild(main);
  root.appendChild(footer);

  Router.render(); // первый рендер

  // Стили
  SafeDOM.injectStyle(`
    .ztc-header, .ztc-footer { display:flex; align-items:center; justify-content:space-between; padding:8px 12px; border-bottom:1px solid #e3e3e3; }
    .ztc-footer { border-top:1px solid #e3e3e3; border-bottom:none; color:#666; font-size:12px; }
    .brand strong { margin-right:8px; }
    .brand .muted { color:#888; font-size:12px; }
    .nav a { margin-right:12px; text-decoration:none; }
    .nav a.active { font-weight:bold; }
    .status .ok { color:#2c7; }
    .status .bad { color:#d44; }
    .view { padding:16px; }
    .card { border:1px solid #e3e3e3; border-radius:8px; padding:12px; margin-bottom:12px; }
    .grid { display:grid; grid-template-columns: repeat(auto-fill,minmax(260px,1fr)); gap:12px; }
    .btn { display:inline-block; padding:6px 10px; border:1px solid #888; border-radius:6px; background:#fafafa; cursor:pointer; user-select:none; }
    .btn:disabled { opacity:.6; cursor:not-allowed; }
    .table { width:100%; border-collapse:collapse; }
    .table th, .table td { border-bottom:1px solid #eee; padding:6px 8px; text-align:left; }
    .muted { color:#777; }
    .toast { position:fixed; right:12px; bottom:12px; background:#333; color:#fff; padding:8px 12px; border-radius:6px; opacity:.95; }
  `);
};

function navLink(href, label) {
  const a = SafeDOM.el("a", { href }, [label]);
  a.addEventListener("click", (e) => {
    // только безопасные навигации (hash)
    if (!href.startsWith("#/")) return;
    document.querySelectorAll(".nav a").forEach(x => x.classList.remove("active"));
    a.classList.add("active");
  });
  return a;
}

/* =========================
 *  ROUTER (HASH)
 * ========================= */
const Router = (() => {
  const routes = {
    "#/dashboard": View.dashboard,
    "#/sessions": View.sessions,
    "#/policies": View.policies,
    "#/audit": View.audit,
  };

  function init() {
    window.addEventListener("hashchange", render);
    if (!location.hash) location.replace("#/dashboard");
    setActiveNav();
    render();
  }
  function setActiveNav() {
    const path = location.hash || "#/dashboard";
    document.querySelectorAll(".nav a").forEach(a => {
      if (a.getAttribute("href") === path) a.classList.add("active");
      else a.classList.remove("active");
    });
  }
  function render() {
    setActiveNav();
    const view = document.getElementById("view");
    if (!view) return;
    SafeDOM.clear(view);
    const path = location.hash || "#/dashboard";
    const fn = routes[path] || View.dashboard;
    try { fn(view); }
    catch (e) { renderError(view, e); }
  }
  return { init, render };
})();

/* =========================
 *  VIEWS
 * ========================= */
const View = (() => {
  function dashboard(root) {
    root.appendChild(SafeDOM.el("h2", {}, ["Панель управления"]));
    root.appendChild(SafeDOM.el("div", { class: "grid" }, [
      card("Профиль", [
        row("Пользователь", App.state.user?.name || "—"),
        row("Роль", App.state.user?.role || "—"),
        row("Организация", App.state.user?.org || "—"),
      ]),
      card("Состояние", [
        row("Сеть", App.state.online ? "Online" : "Offline"),
        row("Регион", CONFIG.region),
        row("Версия", CONFIG.version),
      ]),
      card("Быстрые действия", [
        actionBtn("Обновить данные", async () => {
          await App.actions.loadDashboardData();
          toast("Данные обновлены");
        }),
        " ",
        actionBtn("Сброс токена", () => {
          App.actions.handleUnauth();
        }),
      ])
    ]));
  }

  function sessions(root) {
    root.appendChild(SafeDOM.el("h2", {}, ["Сессии"]));
    tableFrom(root, App.state.cache["sessions"]?.items || [], ["id","user","ip","created_at","status"]);
  }

  function policies(root) {
    root.appendChild(SafeDOM.el("h2", {}, ["Политики доступа"]));
    tableFrom(root, App.state.cache["policies"]?.items || [], ["id","name","effect","updated_at"]);
  }

  function audit(root) {
    root.appendChild(SafeDOM.el("h2", {}, ["Аудит"]));
    tableFrom(root, App.state.cache["audit"]?.items || [], ["ts","actor","action","target","result"]);
  }

  function card(title, children) {
    return SafeDOM.el("div", { class: "card" }, [
      SafeDOM.el("div", { class: "muted", "aria-label":"card-title" }, [title]),
      ...children
    ]);
  }
  function row(k, v) {
    const wrap = SafeDOM.el("div", { class: "row" });
    wrap.appendChild(SafeDOM.el("div", { class: "muted" }, [k]));
    wrap.appendChild(SafeDOM.el("div", {}, [String(v)]));
    return wrap;
  }
  function actionBtn(label, handler) {
    const b = SafeDOM.el("button", { class: "btn", type: "button" }, [label]);
    const safe = SafeDOM.throttle(async () => {
      b.disabled = true;
      try {
        Telemetry.push({ type: "action_click", label });
        await handler();
      } catch (e) {
        toast("Ошибка: " + (e && e.message ? e.message : "действие"));
      } finally { b.disabled = false; }
    }, 800);
    b.addEventListener("click", safe);
    return b;
  }
  function tableFrom(root, rows, cols) {
    const table = SafeDOM.el("table", { class: "table", role:"table" });
    const thead = SafeDOM.el("thead");
    const trh = SafeDOM.el("tr");
    cols.forEach(c => trh.appendChild(SafeDOM.el("th", {}, [c])));
    thead.appendChild(trh);
    const tbody = SafeDOM.el("tbody");
    (rows || []).slice(0, 200).forEach(r => {
      const tr = SafeDOM.el("tr");
      cols.forEach(c => tr.appendChild(SafeDOM.el("td", {}, [sanitizeCell(r?.[c])])));
      tbody.appendChild(tr);
    });
    table.appendChild(thead); table.appendChild(tbody);
    root.appendChild(SafeDOM.el("div", { class: "card" }, [table]));
  }
  function sanitizeCell(v) {
    if (v === null || v === undefined) return "—";
    const s = String(v);
    // Защита от слишком длинных значений
    return s.length > 256 ? s.slice(0, 256) + "…" : s;
  }
  return { dashboard, sessions, policies, audit };
})();

/* =========================
 *  GLOBAL HANDLERS & HELPERS
 * ========================= */
function bindGlobalHandlers() {
  window.addEventListener("online", () => { App.state.online = true; const n=document.getElementById("net-status"); if (n){ n.className="ok"; SafeDOM.text(n,"Online"); } });
  window.addEventListener("offline", () => { App.state.online = false; const n=document.getElementById("net-status"); if (n){ n.className="bad"; SafeDOM.text(n,"Offline"); } });

  window.addEventListener("error", (e) => {
    Telemetry.push({ type: "runtime_error", msg: String(e?.message || "error"), src: String(e?.filename || ""), line: Number(e?.lineno || 0) });
  });
  window.addEventListener("unhandledrejection", (e) => {
    Telemetry.push({ type: "runtime_unhandledrejection", msg: String(e?.reason?.message || e?.reason || "promise") });
  });
}

function secureStyles() {
  // Нет inline‑стилей; единственный инжект через <style nonce="..."> в SafeDOM.injectStyle
}

function toast(message) {
  const t = SafeDOM.el("div", { class: "toast", role: "status", "aria-live": "polite" }, [String(message)]);
  document.body.appendChild(t);
  setTimeout(() => { try { document.body.removeChild(t); } catch {} }, 2500);
}

function renderError(root, err) {
  root.appendChild(SafeDOM.el("div", { class: "card" }, [
    SafeDOM.el("div", { class: "muted" }, ["Ошибка рендера"]),
    SafeDOM.el("pre", {}, [String(err && err.message || err || "error")])
  ]));
  Telemetry.push({ type: "ui_error", msg: String(err && err.message || "render") });
}

function renderFatal(err) {
  const root = document.getElementById("app") || document.body;
  SafeDOM.clear(root);
  root.appendChild(SafeDOM.el("h2", {}, ["Критическая ошибка"]));
  renderError(root, err);
}
