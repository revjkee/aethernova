// SPDX-License-Identifier: Apache-2.0
// clients/web-admin-minimal/main.js
// Минимальная, но промышленная админка на чистом ES-модуле без фреймворков.
// Требует: <script type="module" src="/clients/web-admin-minimal/main.js"></script> и <div id="app"></div>

"use strict";

// =========================
// Конфигурация и окружение
// =========================

const CONFIG = Object.freeze({
  apiBaseUrl: (window.__PIC_CONFIG__ && window.__PIC_CONFIG__.apiBaseUrl) || "/api",
  sseUrl: (window.__PIC_CONFIG__ && window.__PIC_CONFIG__.sseUrl) || "/api/events/stream",
  auth: {
    storageKey: "pic.auth.v1",
    header: "Authorization",
    scheme: "Bearer",
    refreshEndpoint: "/v1/auth/refresh",
    loginEndpoint: "/v1/auth/login",
    logoutEndpoint: "/v1/auth/logout",
  },
  ui: {
    appName: (window.__PIC_CONFIG__ && window.__PIC_CONFIG__.appName) || "Physical Integration Admin",
    themeStorageKey: "pic.theme.v1",
  },
  observability: {
    vitals: true, // сбор веб-виталов (без внешних зависимостей)
    traceSampleRate: 1.0, // 0..1
  },
  features: {
    devices: true,
    firmware: true,
    plans: true,
  },
});

// =========================
// Утилиты: лог, трейс, id
// =========================

const Log = (() => {
  const level = (localStorage.getItem("pic.log.level") || "info").toLowerCase();
  const levels = { trace: 10, debug: 20, info: 30, warn: 40, error: 50 };
  const current = levels[level] || 30;

  function fmt(args) {
    const ts = new Date().toISOString();
    const traceId = Trace.getTraceId() || "-";
    return [`${ts} [trace=${traceId}]`, ...args];
  }
  return {
    trace: (...a) => { if (current <= 10) console.debug(...fmt(a)); },
    debug: (...a) => { if (current <= 20) console.debug(...fmt(a)); },
    info:  (...a) => { if (current <= 30) console.info (...fmt(a)); },
    warn:  (...a) => { if (current <= 40) console.warn (...fmt(a)); },
    error: (...a) => { if (current <= 50) console.error(...fmt(a)); },
  };
})();

const Trace = (() => {
  // W3C Trace Context: traceparent
  function randomHex(bits) {
    // bits должно быть кратно 8; возвращает hex-строку нужной длины
    const bytes = crypto.getRandomValues(new Uint8Array(bits / 8));
    return [...bytes].map(b => b.toString(16).padStart(2, "0")).join("");
  }

  let current = null; // {traceId, spanId, sampled}
  function maybeSample() {
    return Math.random() < CONFIG.observability.traceSampleRate;
  }
  function ensure() {
    if (!current) {
      current = {
        traceId: randomHex(128),
        spanId: randomHex(64),
        sampled: maybeSample(),
      };
    }
    return current;
  }
  function childSpanId() {
    return randomHex(64);
  }
  function header(spanId) {
    const ctx = ensure();
    const flags = ctx.sampled ? "01" : "00";
    return `00-${ctx.traceId}-${spanId || ctx.spanId}-${flags}`;
  }
  function getTraceId() {
    return ensure().traceId;
  }
  return { ensure, childSpanId, header, getTraceId, };
})();

// =========================
// Безопасные DOM-утилиты
// =========================

const Dom = (() => {
  function el(tag, props = {}, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(props || {})) {
      if (v == null) continue;
      if (k === "class") node.className = String(v);
      else if (k === "dataset") for (const [dk, dv] of Object.entries(v)) node.dataset[dk] = String(dv);
      else if (k.startsWith("on") && typeof v === "function") node.addEventListener(k.substring(2), v, { passive: true });
      else if (k === "aria") for (const [ak, av] of Object.entries(v)) node.setAttribute(`aria-${ak}`, String(av));
      else if (k === "for") node.htmlFor = String(v);
      else node.setAttribute(k, String(v));
    }
    for (const c of children.flat()) {
      if (c == null) continue;
      if (typeof c === "string" || typeof c === "number") node.appendChild(document.createTextNode(String(c)));
      else node.appendChild(c);
    }
    return node;
  }
  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
  function mount(root, child) { clear(root); root.appendChild(child); }
  function announce(msg) {
    // a11y live region
    let region = document.getElementById("a11y-live");
    if (!region) {
      region = el("div", { id: "a11y-live", role: "status", aria: { live: "polite" }, class: "sr-only" });
      document.body.appendChild(region);
    }
    region.textContent = msg;
  }
  return { el, mount, clear, announce };
})();

// =========================
// Хранилище auth/тема
// =========================

const Store = (() => {
  function getJSON(key, fallback = null) {
    try { const v = localStorage.getItem(key); return v ? JSON.parse(v) : fallback; } catch { return fallback; }
  }
  function setJSON(key, val) {
    localStorage.setItem(key, JSON.stringify(val));
  }
  function del(key) { localStorage.removeItem(key); }
  return { getJSON, setJSON, del };
})();

const Theme = (() => {
  function apply(theme) {
    const t = theme || Store.getJSON(CONFIG.ui.themeStorageKey) || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    document.documentElement.dataset.theme = t;
    Store.setJSON(CONFIG.ui.themeStorageKey, t);
  }
  function toggle() {
    const cur = document.documentElement.dataset.theme || "light";
    apply(cur === "light" ? "dark" : "light");
  }
  return { apply, toggle };
})();

// =========================
// Локализация (минимальная)
// =========================

const I18N = (() => {
  const dict = {
    ru: {
      login: "Вход",
      logout: "Выход",
      username: "Пользователь",
      password: "Пароль",
      signIn: "Войти",
      devices: "Устройства",
      firmware: "Прошивки",
      plans: "Планы",
      search: "Поиск",
      loading: "Загрузка",
      error: "Ошибка",
      retry: "Повтор",
      theme: "Тема",
      light: "Светлая",
      dark: "Темная",
      noData: "Нет данных",
    },
    en: {
      login: "Login",
      logout: "Logout",
      username: "Username",
      password: "Password",
      signIn: "Sign in",
      devices: "Devices",
      firmware: "Firmware",
      plans: "Plans",
      search: "Search",
      loading: "Loading",
      error: "Error",
      retry: "Retry",
      theme: "Theme",
      light: "Light",
      dark: "Dark",
      noData: "No data",
    },
  };
  const lang = (navigator.language || "en").slice(0, 2) in dict ? (navigator.language || "en").slice(0, 2) : "en";
  function t(key) { return (dict[lang] && dict[lang][key]) || key; }
  return { t, lang };
})();

// =========================
// Аутентификация и RBAC
// =========================

const Auth = (() => {
  const key = CONFIG.auth.storageKey;
  const bc = ("BroadcastChannel" in window) ? new BroadcastChannel("pic-auth") : null;

  function read() { return Store.getJSON(key, null); } // {accessToken, refreshToken, user:{name,roles:[]}, exp}
  function isAuthenticated() {
    const s = read();
    if (!s || !s.accessToken) return false;
    // Быстрая проверка истечения (exp в секундах), допускаем 30с дрифт
    if (typeof s.exp === "number" && s.exp * 1000 < Date.now() + 30_000) return false;
    return true;
  }
  function roles() { return (read() && read().user && read().user.roles) || []; }
  function hasRole(role) { return roles().includes(role); }

  async function login(username, password) {
    const res = await Api.request("POST", CONFIG.auth.loginEndpoint, { username, password }, { auth: false });
    const body = await res.json();
    // ожидаем {access_token, refresh_token?, user:{name,roles:[]}, exp}
    if (!body || !body.access_token) throw new Error("Auth failed");
    const state = {
      accessToken: body.access_token,
      refreshToken: body.refresh_token || null,
      user: body.user || { name: username, roles: [] },
      exp: body.exp || null,
    };
    Store.setJSON(key, state);
    bc && bc.postMessage({ type: "login" });
    return state;
  }

  async function logout(remote = true) {
    const s = read();
    Store.del(key);
    bc && bc.postMessage({ type: "logout" });
    if (remote && s && s.accessToken) {
      try { await Api.request("POST", CONFIG.auth.logoutEndpoint, {}, { retries: 0 }).catch(() => {}); } catch {}
    }
  }

  async function refresh() {
    const s = read();
    if (!s || !s.refreshToken) throw new Error("No refresh token");
    const res = await Api.request("POST", CONFIG.auth.refreshEndpoint, { refresh_token: s.refreshToken }, { auth: false, retries: 0 });
    const body = await res.json();
    if (!body || !body.access_token) throw new Error("Refresh failed");
    const state = { ...s, accessToken: body.access_token, exp: body.exp || s.exp };
    Store.setJSON(key, state);
    bc && bc.postMessage({ type: "refresh" });
    return state;
  }

  bc && (bc.onmessage = (ev) => {
    if (ev && ev.data && ev.data.type === "logout") {
      Router.go("#/login");
    }
  });

  return { read, isAuthenticated, roles, hasRole, login, logout, refresh };
})();

// =========================
/* API-клиент: fetch с таймаутом, ретраями, traceparent, JSON */
// =========================

const Api = (() => {
  function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

  async function request(method, path, body = undefined, opts = {}) {
    const {
      headers = {},
      timeoutMs = 10_000,
      retries = 2,
      auth = true,
      signal,
      query,
    } = opts;

    const url = new URL((CONFIG.apiBaseUrl + path).replace(/\/{2,}/g, "/"), window.location.origin);
    if (query && typeof query === "object") {
      Object.entries(query).forEach(([k, v]) => {
        if (v != null) url.searchParams.set(k, String(v));
      });
    }

    const ac = new AbortController();
    const to = setTimeout(() => ac.abort(new DOMException("Timeout", "AbortError")), timeoutMs);
    const spanId = Trace.childSpanId();
    const traceHeader = Trace.header(spanId);

    const h = new Headers(headers || {});
    h.set("Content-Type", "application/json");
    h.set("Accept", "application/json");
    h.set("traceparent", traceHeader);
    h.set("X-Request-Id", Trace.getTraceId());

    const authState = Auth.read();
    if (auth && authState && authState.accessToken) {
      h.set(CONFIG.auth.header, `${CONFIG.auth.scheme} ${authState.accessToken}`);
    }

    const fetchOpts = {
      method,
      headers: h,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: signal || ac.signal,
      credentials: "same-origin",
      cache: "no-store",
      redirect: "follow",
      referrerPolicy: "no-referrer",
      mode: "cors",
    };

    let attempt = 0;
    let lastErr = null;
    while (attempt <= retries) {
      try {
        const resp = await fetch(url.toString(), fetchOpts);
        clearTimeout(to);

        if (resp.status === 401 && auth && Auth.read()?.refreshToken) {
          // попытка обновить токен ровно один раз
          Log.info("401, trying token refresh");
          try {
            await Auth.refresh();
            // повтор запроса без увеличения attempt
            h.set(CONFIG.auth.header, `${CONFIG.auth.scheme} ${Auth.read().accessToken}`);
            continue;
          } catch (e) {
            await Auth.logout(false);
            throw new Error("Unauthorized");
          }
        }

        if (resp.status >= 500 || resp.status === 429) {
          if (attempt < retries) {
            const backoff = Math.min(1000 * Math.pow(2, attempt) + Math.random() * 250, 5000);
            Log.warn("Server error %d, retry in %d ms", resp.status, backoff);
            await sleep(backoff);
            attempt++;
            continue;
          }
        }

        if (!resp.ok) {
          const text = await resp.text().catch(() => "");
          const err = new Error(`HTTP ${resp.status} ${resp.statusText} ${text}`.trim());
          err.status = resp.status;
          throw err;
        }

        return resp;
      } catch (e) {
        clearTimeout(to);
        lastErr = e;
        if (e && e.name === "AbortError") {
          if (attempt < retries) {
            const backoff = Math.min(500 * Math.pow(2, attempt), 3000);
            await sleep(backoff);
            attempt++;
            continue;
          }
        }
        if (attempt < retries) {
          await sleep(300 * (attempt + 1));
          attempt++;
          continue;
        }
        throw lastErr || e;
      }
    }
    // сюда не придем
  }

  async function json(method, path, body, opts) {
    const resp = await request(method, path, body, opts);
    const ct = resp.headers.get("Content-Type") || "";
    if (!ct.includes("application/json")) return {};
    return resp.json();
  }

  return { request, json };
})();

// =========================
// SSE клиент (опционально)
// =========================

const Events = (() => {
  let es = null;
  function connect() {
    if (!window.EventSource) return;
    if (es) { es.close(); es = null; }
    const params = new URLSearchParams({ trace: Trace.getTraceId() });
    es = new EventSource(`${CONFIG.sseUrl}?${params.toString()}`, { withCredentials: true });
    es.onopen = () => Log.info("SSE connected");
    es.onerror = () => Log.warn("SSE error");
    es.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data);
        Router.notify("sse", msg);
      } catch {}
    };
  }
  function close() { if (es) es.close(); es = null; }
  return { connect, close };
})();

// =========================
// Роутер (hash-based)
// =========================

const Router = (() => {
  const routes = new Map(); // "#/path" -> view
  const listeners = new Set();

  function on(event, fn) {
    listeners.add({ event, fn });
    return () => listeners.delete({ event, fn });
  }
  function notify(event, payload) {
    for (const l of listeners) if (l.event === event) try { l.fn(payload); } catch {}
  }

  function register(path, view) { routes.set(path, view); }
  function currentPath() { return location.hash || "#/devices"; }
  function go(hash) {
    if (location.hash === hash) render();
    else location.hash = hash;
  }
  window.addEventListener("hashchange", () => render());

  async function render() {
    const path = currentPath();
    const view = routes.get(path) || routes.get("#/404");
    if (!view) return;
    if (view.auth && !Auth.isAuthenticated()) {
      return go("#/login");
    }
    await App.renderView(view);
  }

  return { register, render, go, on, notify, currentPath };
})();

// =========================
// Компоненты UI
// =========================

const UI = (() => {
  function Spinner(label = I18N.t("loading")) {
    return Dom.el("div", { class: "spinner", role: "status", aria: { busy: "true" } }, label);
  }
  function ErrorCard(err, retry) {
    return Dom.el("div", { class: "card error", role: "alert" },
      Dom.el("div", { class: "title" }, I18N.t("error")),
      Dom.el("pre", {}, String(err && err.message || err || "Unknown")),
      retry ? Dom.el("button", { class: "btn", onClick: retry }, I18N.t("retry")) : null
    );
  }
  function Navbar(state) {
    const isAuth = Auth.isAuthenticated();
    const theme = document.documentElement.dataset.theme || "light";
    return Dom.el("header", { class: "navbar" },
      Dom.el("div", { class: "brand" }, CONFIG.ui.appName),
      Dom.el("nav", {},
        Dom.el("a", { href: "#/devices" }, I18N.t("devices")),
        CONFIG.features.firmware ? Dom.el("a", { href: "#/firmware" }, I18N.t("firmware")) : null,
        CONFIG.features.plans ? Dom.el("a", { href: "#/plans" }, I18N.t("plans")) : null,
      ),
      Dom.el("div", { class: "actions" },
        Dom.el("button", { class: "btn", onClick: () => { Theme.toggle(); Navbar.update(); } }, `${I18N.t("theme")}: ${theme}`),
        isAuth
          ? Dom.el("button", { class: "btn", onClick: async () => { await Auth.logout(true); Router.go("#/login"); } }, I18N.t("logout"))
          : Dom.el("a", { class: "btn", href: "#/login" }, I18N.t("login"))
      )
    );
  }
  Navbar.update = () => {
    const header = document.querySelector("header.navbar");
    if (header) header.replaceWith(Navbar({}));
  };

  function Table(headers, rows) {
    const thead = Dom.el("thead", {}, Dom.el("tr", {}, ...headers.map(h => Dom.el("th", {}, h))));
    const tbody = Dom.el("tbody", {},
      ...(rows.length ? rows.map(r => Dom.el("tr", {}, ...r.map(cell => Dom.el("td", {}, cell)))) : [
        Dom.el("tr", {}, Dom.el("td", { colSpan: String(headers.length) }, I18N.t("noData")))
      ])
    );
    return Dom.el("table", { class: "table", role: "table" }, thead, tbody);
  }

  return { Spinner, ErrorCard, Navbar, Table };
})();

// =========================
// Представления (views)
// =========================

const Views = (() => {
  const root = document.getElementById("app");

  function layout(content) {
    const container = Dom.el("div", { class: "container" }, content);
    return Dom.el("div", { class: "app" }, UI.Navbar({}), container);
  }

  // Login
  const Login = {
    path: "#/login",
    auth: false,
    async render() {
      const uId = "login-user", pId = "login-pass";
      const form = Dom.el("form", { class: "card" },
        Dom.el("h2", {}, I18N.t("login")),
        Dom.el("label", { for: uId }, I18N.t("username")),
        Dom.el("input", { id: uId, name: "username", type: "text", required: "true", autocomplete: "username" }),
        Dom.el("label", { for: pId }, I18N.t("password")),
        Dom.el("input", { id: pId, name: "password", type: "password", required: "true", autocomplete: "current-password" }),
        Dom.el("button", { class: "btn", type: "submit" }, I18N.t("signIn"))
      );
      form.addEventListener("submit", async (e) => {
        e.preventDefault();
        const fd = new FormData(form);
        const username = fd.get("username"); const password = fd.get("password");
        Dom.announce("Authenticating");
        try {
          await Auth.login(String(username), String(password));
          Router.go("#/devices");
        } catch (err) {
          Dom.mount(root, layout(UI.ErrorCard(err, () => Router.go("#/login"))));
        }
      });
      Dom.mount(root, layout(form));
      document.getElementById(uId)?.focus();
    },
  };

  // Devices
  const Devices = {
    path: "#/devices",
    auth: true,
    async render() {
      Dom.mount(root, layout(UI.Spinner()));
      try {
        const data = await Api.json("GET", "/v1/devices", null, { query: { limit: 50 } });
        const rows = (data.items || []).map(d =>
          [d.name || d.id, `${d.vendor || ""}/${d.product || ""}`, d.current_fw_version || "-", d.site || "-", d.channel || "-"]
        );
        const table = UI.Table(["Name", "Model", "FW", "Site", "Channel"], rows);
        const search = Dom.el("input", { type: "search", placeholder: I18N.t("search"), class: "search", onInput: (e) => {
          const q = e.target.value.toLowerCase();
          // простая фильтрация
          [...table.querySelectorAll("tbody tr")].forEach(tr => {
            const txt = tr.textContent.toLowerCase();
            tr.style.display = txt.includes(q) ? "" : "none";
          });
        }});
        const card = Dom.el("div", { class: "card" }, Dom.el("h2", {}, I18N.t("devices")), search, table);
        Dom.mount(root, layout(card));
      } catch (err) {
        Dom.mount(root, layout(UI.ErrorCard(err, () => Devices.render())));
      }
    },
  };

  // Firmware
  const Firmware = {
    path: "#/firmware",
    auth: true,
    async render() {
      Dom.mount(root, layout(UI.Spinner()));
      try {
        const data = await Api.json("GET", "/v1/firmware", null, { query: { limit: 50 } });
        const rows = (data.items || []).map(f => [f.version, `${f.vendor}/${f.product}/${f.hw_revision}`, f.channel, f.size_bytes]);
        Dom.mount(root, layout(Dom.el("div", { class: "card" }, Dom.el("h2", {}, I18N.t("firmware")), UI.Table(["Version", "Target", "Channel", "Size"], rows))));
      } catch (err) {
        Dom.mount(root, layout(UI.ErrorCard(err, () => Firmware.render())));
      }
    },
  };

  // Plans
  const Plans = {
    path: "#/plans",
    auth: true,
    async render() {
      Dom.mount(root, layout(UI.Spinner()));
      try {
        const data = await Api.json("GET", "/v1/plans", null, { query: { limit: 50 } });
        const rows = (data.items || []).map(p => [p.id, p.firmware_uid, p.batch_size, p.max_parallel, p.created_by]);
        Dom.mount(root, layout(Dom.el("div", { class: "card" }, Dom.el("h2", {}, I18N.t("plans")), UI.Table(["ID", "Firmware", "Batch", "Parallel", "Author"], rows))));
      } catch (err) {
        Dom.mount(root, layout(UI.ErrorCard(err, () => Plans.render())));
      }
    },
  };

  const NotFound = {
    path: "#/404",
    auth: false,
    async render() {
      Dom.mount(root, layout(Dom.el("div", { class: "card" }, Dom.el("h2", {}, "404"), Dom.el("p", {}, "Not found"))));
    },
  };

  return { Login, Devices, Firmware, Plans, NotFound };
})();

// =========================
// Веб-виталы (минимально)
// =========================

const Vitals = (() => {
  if (!CONFIG.observability.vitals || !("PerformanceObserver" in window)) return { start: ()=>{} };
  function observe() {
    try {
      const send = (name, value) => {
        Log.debug("WebVital", name, value);
        // пример отправки на бекенд:
        // Api.request("POST", "/v1/telemetry/webvitals", { name, value }, { retries: 0 }).catch(()=>{});
      };
      const po = new PerformanceObserver((list) => {
        list.getEntries().forEach((e) => {
          if (e.name === "first-contentful-paint") send("FCP", Math.round(e.startTime + e.duration));
        });
      });
      po.observe({ type: "paint", buffered: true });
      const lcp = new PerformanceObserver((list) => {
        const entries = list.getEntries();
        const last = entries[entries.length - 1];
        if (last) Log.debug("LCP", Math.round(last.startTime));
      });
      lcp.observe({ type: "largest-contentful-paint", buffered: true });
    } catch {}
  }
  return { start: observe };
})();

// =========================
// Приложение
// =========================

const App = (() => {
  async function init() {
    Theme.apply();
    // Регистрация роутов
    Router.register(Views.Login.path, Views.Login);
    Router.register(Views.Devices.path, Views.Devices);
    CONFIG.features.firmware && Router.register(Views.Firmware.path, Views.Firmware);
    CONFIG.features.plans && Router.register(Views.Plans.path, Views.Plans);
    Router.register(Views.NotFound.path, Views.NotFound);

    // Подключить SSE после входа
    if (Auth.isAuthenticated()) {
      Events.connect();
    }
    Router.on("sse", (msg) => {
      Log.debug("SSE", msg && msg.type);
      // при необходимости обновляйте часть UI по msg
    });

    Vitals.start();
    await Router.render();
  }

  async function renderView(view) {
    try {
      await view.render();
      UI.Navbar.update();
    } catch (e) {
      const root = document.getElementById("app");
      Dom.mount(root, UI.ErrorCard(e, () => Router.render()));
    }
  }

  return { init, renderView };
})();

// =========================
// Старт
// =========================

window.addEventListener("DOMContentLoaded", () => {
  try {
    App.init();
  } catch (e) {
    console.error("Fatal init error", e);
    const root = document.getElementById("app") || document.body;
    root.textContent = "Fatal error";
  }
});

// =========================
// Базовые стили (минимум)
// =========================
// Поддерживает строгую CSP: стили лучше вынести в отдельный CSS.
// Здесь оставлен небольшой инлайн для удобства демо окружений.
(() => {
  const css = `
:root { color-scheme: light dark; --bg:#fff; --fg:#111; --muted:#666; --card:#f6f6f6; --border:#ddd; --btn:#0b5; }
:root[data-theme="dark"] { --bg:#111; --fg:#eee; --muted:#aaa; --card:#1b1b1b; --border:#333; --btn:#2d8; }
*{box-sizing:border-box} html,body,#app{height:100%} body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.4 system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,"Noto Sans",sans-serif}
a{color:inherit;text-decoration:none;margin-right:12px}
.container{max-width:1200px;margin:0 auto;padding:16px}
.navbar{display:flex;align-items:center;justify-content:space-between;padding:10px 16px;border-bottom:1px solid var(--border);background:var(--card);position:sticky;top:0;z-index:10}
.navbar .brand{font-weight:600}
.btn{background:var(--btn);color:#fff;border:none;border-radius:6px;padding:8px 12px;cursor:pointer}
.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:16px;margin-top:16px}
.table{width:100%;border-collapse:collapse}
.table th,.table td{padding:8px;border-bottom:1px solid var(--border);text-align:left}
.search{margin:8px 0;padding:8px;border-radius:6px;border:1px solid var(--border);width:100%}
.spinner{padding:16px;color:var(--muted)}
.error .title{font-weight:600;margin-bottom:8px}
.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
`;
  const style = document.createElement("style");
  style.appendChild(document.createTextNode(css));
  document.head.appendChild(style);
})();
