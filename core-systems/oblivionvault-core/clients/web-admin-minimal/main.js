// file: clients/web-admin-minimal/main.js
// Industrial-grade entrypoint for OblivionVault web-admin (no external deps).

/* global window, document, performance */
"use strict";

/**
 * =========================
 * Section 0. Basic utilities
 * =========================
 */

/** @template T @param {T} v @returns {v is Exclude<T, null|undefined>} */
const isDef = (v) => v !== null && v !== undefined;

/** @param {number} ms */
const sleep = (ms) => new Promise((res) => setTimeout(res, ms));

/** RFC4122 v4 uuid (crypto-based) */
const uuid4 = () => {
  if (crypto?.randomUUID) return crypto.randomUUID();
  const a = new Uint8Array(16); crypto.getRandomValues(a);
  a[6] = (a[6] & 0x0f) | 0x40; a[8] = (a[8] & 0x3f) | 0x80;
  const h = [...a].map((b) => b.toString(16).padStart(2, "0")).join("");
  return `${h.substring(0,8)}-${h.substring(8,12)}-${h.substring(12,16)}-${h.substring(16,20)}-${h.substring(20)}`;
};

/** Base64url decode (browser-safe) */
const b64json = (s) => {
  try {
    const pad = "=".repeat((4 - (s.length % 4)) % 4);
    const base = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
    const text = atob(base);
    return JSON.parse(new TextDecoder().decode(Uint8Array.from(text, c => c.charCodeAt(0))));
  } catch { return null; }
};

/** Stable string hash (FNV-1a 32-bit) */
const hash32 = (str) => {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = (h * 0x01000193) >>> 0; }
  return h >>> 0;
};

/** Clamp */
const clamp = (v, min, max) => Math.max(min, Math.min(max, v));

/**
 * =========================
 * Section 1. Configuration
 * =========================
 * Config precedence: window.__APP_CONFIG__ -> <meta data-...> -> defaults.
 */

const DefaultConfig = Object.freeze({
  service: "oblivionvault-web-admin",
  env: "dev",
  apiBaseUrl: "/api",
  auth: {
    loginPath: "/auth/login",
    refreshPath: "/auth/refresh",
    logoutPath: "/auth/logout",
    /** If true, the refresh token is httpOnly cookie; we only call refresh endpoint. */
    refreshCookieMode: true,
  },
  telemetry: {
    rumEndpoint: "/observability/rum",
    sampleRate: 0.1,
  },
  security: {
    // Disallow running in frames (js-side bust, server must also send X-Frame-Options/ CSP)
    breakOutOfFrame: true,
    // redact keys in client logs
    redactKeys: ["password","pass","secret","token","api_key","authorization","cookie","set-cookie","x-api-key","refresh_token","access_token"],
  },
  router: {
    defaultRoute: "/dashboard",
  }
});

/** @returns {Record<string, any>} */
function readConfig() {
  /** @type {any} */
  const wcfg = window.__APP_CONFIG__;
  if (wcfg && typeof wcfg === "object") return deepMerge(DefaultConfig, wcfg);

  const meta = (name, def = null) => {
    const el = document.querySelector(`meta[name="${name}"]`);
    return el?.getAttribute("content") ?? def;
  };
  const cfg = {
    env: meta("app:env") || DefaultConfig.env,
    apiBaseUrl: meta("app:api-base") || DefaultConfig.apiBaseUrl,
    telemetry: {
      rumEndpoint: meta("app:rum-endpoint") || DefaultConfig.telemetry.rumEndpoint,
      sampleRate: parseFloat(meta("app:rum-sample") || `${DefaultConfig.telemetry.sampleRate}`),
    }
  };
  return deepMerge(DefaultConfig, cfg);
}

/** @param {any} a @param {any} b */
function deepMerge(a, b) {
  if (Array.isArray(a) && Array.isArray(b)) return [...a, ...b];
  if (typeof a === "object" && typeof b === "object" && a && b) {
    const out = {...a};
    for (const k of Object.keys(b)) out[k] = k in a ? deepMerge(a[k], b[k]) : b[k];
    return out;
  }
  return isDef(b) ? b : a;
}

const CONFIG = readConfig();

/**
 * =========================
 * Section 2. Logger (JSON)
 * =========================
 */

const Logger = (() => {
  const redactKeys = new Set((CONFIG.security?.redactKeys || []).map(k => String(k).toLowerCase()));
  /** @param {any} v */
  const redact = (v) => {
    try {
      if (Array.isArray(v)) return v.map(redact);
      if (v && typeof v === "object") {
        const o = {}; for (const [k, val] of Object.entries(v)) {
          o[k] = redactKeys.has(k.toLowerCase()) ? "***" : redact(val);
        } return o;
      }
      if (typeof v === "string") {
        // redact common inline tokens
        return v
          .replace(/(Bearer\s+)[A-Za-z0-9\-\._~\+\/]+=*/g, "$1***")
          .replace(/(?i)(token|secret|apikey|api_key|password)\s*[:=]\s*[A-Za-z0-9\-\._~\+\/]+=*/g, "***");
      }
      return v;
    } catch { return "***"; }
  };

  const context = {
    sessionId: uuid4(),
    requestId: uuid4(),
  };

  /** @param {"debug"|"info"|"warn"|"error"} level @param {string} msg @param {Record<string, any>=} extra */
  function log(level, msg, extra) {
    const evt = {
      ts: new Date().toISOString(),
      level: level.toUpperCase(),
      service: CONFIG.service,
      env: CONFIG.env,
      message: msg,
      ...context,
      ...(extra ? redact(extra) : null),
    };
    const line = JSON.stringify(evt);
    // console sink
    switch (level) {
      case "debug": console.debug(line); break;
      case "info": console.info(line); break;
      case "warn": console.warn(line); break;
      default: console.error(line); break;
    }
    // optional: remote sink via Beacon (fire-and-forget)
    // keep minimal; real pipeline should be handled by backend collector
    try {
      if (Math.random() < 0.01 && navigator.sendBeacon) {
        const blob = new Blob([line], {type: "application/json"});
        navigator.sendBeacon(CONFIG.telemetry?.rumEndpoint || "/observability/rum", blob);
      }
    } catch { /* noop */ }
  }

  return {
    debug: (m, e) => log("debug", m, e),
    info: (m, e) => log("info", m, e),
    warn: (m, e) => log("warn", m, e),
    error: (m, e) => log("error", m, e),
    setRequestId: (rid) => { context.requestId = rid || uuid4(); },
    getContext: () => ({...context}),
  };
})();


/**
 * ======================================
 * Section 3. Global error & security hooks
 * ======================================
 */

// Anti-framing (client-side). Server must also enforce via headers.
if (CONFIG.security?.breakOutOfFrame && window.top !== window.self) {
  try { window.top.location = window.location; } catch { window.location.replace(window.location.href); }
}

// Global error handlers
window.addEventListener("error", (e) => {
  Logger.error("unhandled_error", { filename: e.filename, lineno: e.lineno, colno: e.colno, message: String(e.message) });
});
window.addEventListener("unhandledrejection", (e) => {
  Logger.error("unhandled_rejection", { reason: String(e.reason) });
});

// Offline/online indicator
window.addEventListener("offline", () => Banner.show("Вы офлайн. Некоторые функции недоступны.", "warn"));
window.addEventListener("online", () => Banner.hide());


/**
 * =========================
 * Section 4. Tiny state store
 * =========================
 */

const Store = (() => {
  /** @type {{user: null|{sub:string, roles:string[], name?:string}, accessToken?:string}} */
  const state = { user: null, accessToken: undefined };
  /** @type {Set<() => void>} */
  const subs = new Set();

  const notify = () => subs.forEach((fn) => { try { fn(); } catch {} });

  return {
    getState: () => ({...state}),
    setState: (patch) => { Object.assign(state, patch || {}); notify(); },
    subscribe: (fn) => { subs.add(fn); return () => subs.delete(fn); },
    reset: () => { state.user = null; state.accessToken = undefined; notify(); }
  };
})();


/**
 * =================================
 * Section 5. Token store & session
 * =================================
 * Strategy: keep accessToken in-memory; mirror to sessionStorage for page reloads.
 */

const Session = (() => {
  const KEY = "ov_session";
  const read = () => {
    try { return JSON.parse(sessionStorage.getItem(KEY) || "null"); } catch { return null; }
  };
  const write = (data) => {
    try { if (data) sessionStorage.setItem(KEY, JSON.stringify(data)); else sessionStorage.removeItem(KEY); } catch {}
  };

  /** @param {string} token */
  function setAccessToken(token) {
    Store.setState({ accessToken: token });
    write({ accessToken: token });
  }

  function loadFromStorage() {
    const data = read();
    if (data?.accessToken) Store.setState({ accessToken: data.accessToken });
  }

  function clear() {
    write(null);
    Store.reset();
  }

  return { setAccessToken, loadFromStorage, clear };
})();

/**
 * =========================
 * Section 6. Trace context
 * =========================
 */

const Trace = (() => {
  // Minimal W3C traceparent header generator (not a full OTel)
  const newTraceId = () => uuid4().replace(/-/g, "");
  const newSpanId = () => uuid4().replace(/-/g, "").substring(0, 16);
  function traceparent() {
    const tid = newTraceId();
    const sid = newSpanId();
    return `00-${tid}-${sid}-01`;
  }
  return { traceparent };
})();

/**
 * =========================
 * Section 7. API client
 * =========================
 */

const Api = (() => {
  const base = (CONFIG.apiBaseUrl || "/api").replace(/\/+$/, "");
  const maxAttempts = 4;

  let failures = 0;
  let circuitOpenUntil = 0;

  const isCircuitOpen = () => Date.now() < circuitOpenUntil;
  const openCircuit = () => {
    failures++;
    const backoffMs = clamp(250 * 2 ** failures, 1000, 15000);
    circuitOpenUntil = Date.now() + backoffMs;
    Logger.warn("api_circuit_open", { failures, backoffMs });
  };
  const closeCircuit = () => { failures = 0; circuitOpenUntil = 0; };

  /** @param {RequestInfo} url @param {RequestInit & {auth?: boolean, idempotent?: boolean}} init */
  async function request(url, init = {}) {
    if (isCircuitOpen()) throw new Error("API circuit is open");
    const tparent = Trace.traceparent();
    const idempotent = !!init.idempotent;
    /** @type {RequestInit} */
    const req = {
      method: init.method || "GET",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-Request-Id": uuid4(),
        "traceparent": tparent,
        ...(init.headers || {}),
      },
      body: init.body,
      credentials: "include", // allow refresh cookie if server uses it
      mode: "same-origin",
      cache: "no-store",
    };

    // Inject access token if present
    const { accessToken } = Store.getState();
    if (accessToken) (req.headers)["Authorization"] = `Bearer ${accessToken}`;

    // Attempts loop with exponential backoff for network/5xx/429
    let attempt = 0;
    while (true) {
      attempt++;
      try {
        const res = await fetch(`${base}${url}`, req);
        if (res.status === 401 && init.auth !== false) {
          // try refresh once
          const refreshed = await tryRefresh();
          if (refreshed) {
            // re-inject new token and retry once without increasing attempt count
            const { accessToken: tok } = Store.getState();
            if (tok) (req.headers)["Authorization"] = `Bearer ${tok}`;
            const again = await fetch(`${base}${url}`, req);
            if (again.ok) { closeCircuit(); return parseJson(again); }
            if (again.status === 401) { await Auth.logoutSilent(); throw new Error("Unauthorized"); }
            if (again.ok === false) throw again;
          } else {
            await Auth.logoutSilent();
            throw new Error("Unauthorized");
          }
        }

        if (res.status === 429 || res.status >= 500) {
          if (attempt < maxAttempts && (idempotent || req.method === "GET")) {
            const delay = jitterBackoff(attempt);
            Logger.warn("api_retry", { url, attempt, status: res.status, delay });
            await sleep(delay);
            continue;
          }
        }

        if (!res.ok) {
          const body = await safeText(res);
          throw new Error(`HTTP ${res.status}: ${body.slice(0,200)}`);
        }
        closeCircuit();
        return parseJson(res);
      } catch (err) {
        if (attempt < maxAttempts && (idempotent || req.method === "GET")) {
          const delay = jitterBackoff(attempt);
          Logger.warn("api_retry_exception", { url, attempt, delay, error: String(err) });
          await sleep(delay);
          continue;
        } else {
          openCircuit();
          throw err;
        }
      }
    }
  }

  async function parseJson(res) {
    const text = await res.text();
    if (!text) return null;
    try { return JSON.parse(text); }
    catch { return text; }
  }

  async function safeText(res) {
    try { return await res.text(); } catch { return ""; }
  }

  function jitterBackoff(attempt) {
    const base = Math.min(1000 * 2 ** (attempt - 1), 8000);
    return Math.floor(Math.random() * base);
  }

  async function tryRefresh() {
    try {
      if (!CONFIG.auth?.refreshCookieMode) {
        // Token-based refresh not used in this template
        return false;
      }
      const res = await fetch(`${base}${CONFIG.auth.refreshPath}`, {
        method: "POST",
        headers: { "Accept": "application/json", "traceparent": Trace.traceparent() },
        credentials: "include",
      });
      if (!res.ok) return false;
      /** Server may return new access token in body, or set in cookie and echo token */
      const data = await parseJson(res);
      const token = data?.access_token || null;
      if (token) Session.setAccessToken(token);
      return true;
    } catch { return false; }
  }

  return {
    get: (url, opts) => request(url, { ...opts, method: "GET", idempotent: true }),
    post: (url, body, opts) => request(url, { ...opts, method: "POST", body: JSON.stringify(body) }),
    put: (url, body, opts) => request(url, { ...opts, method: "PUT", body: JSON.stringify(body) }),
    del: (url, opts) => request(url, { ...opts, method: "DELETE" }),
  };
})();

/**
 * =========================
 * Section 8. Auth helpers
 * =========================
 */

const Auth = (() => {
  /** @param {string} token */
  function setToken(token) {
    Session.setAccessToken(token);
    const user = decodeUserFromJWT(token);
    Store.setState({ user });
  }

  function decodeUserFromJWT(token) {
    try {
      const [, payload] = token.split(".");
      const data = b64json(payload) || {};
      /** roles claim may be "roles" or "role" or "realm_access.roles" (Keycloak) */
      const roles = Array.isArray(data.roles) ? data.roles
        : Array.isArray(data.role) ? data.role
        : Array.isArray(data?.realm_access?.roles) ? data.realm_access.roles
        : [];
      return { sub: String(data.sub || data.user_id || ""), roles, name: data.name || data.preferred_username || "" };
    } catch { return { sub: "", roles: [] }; }
  }

  async function login(username, password) {
    const res = await Api.post(CONFIG.auth.loginPath, { username, password }, { auth: false });
    const token = res?.access_token;
    if (!token) throw new Error("Login failed");
    setToken(token);
    return true;
  }

  async function logout() {
    try {
      await Api.post(CONFIG.auth.logoutPath, {}, { auth: false });
    } catch {}
    Session.clear();
    Router.go("/login");
  }

  async function logoutSilent() {
    try { await Api.post(CONFIG.auth.logoutPath, {}, { auth: false }); } catch {}
    Session.clear();
  }

  function hasRole(role) {
    const { user } = Store.getState();
    return !!user && user.roles.includes(role);
  }

  return { login, logout, logoutSilent, hasRole, setToken };
})();

/**
 * =========================
 * Section 9. Router (hash)
 * =========================
 */

const Router = (() => {
  /** @type {Record<string, (params: Record<string,string>) => void>} */
  const routes = Object.create(null);

  function parseHash() {
    const raw = window.location.hash.replace(/^#/, "");
    const [path, query = ""] = raw.split("?");
    const params = Object.fromEntries(new URLSearchParams(query));
    return { path: path || "/", params };
  }

  function onChange() {
    const { path, params } = parseHash();
    (routes[path] || routes["/404"] || (() => Views.NotFound()))(params);
  }

  function add(path, handler) { routes[path] = handler; }

  function go(path, qs) {
    const url = "#" + path + (qs ? `?${new URLSearchParams(qs).toString()}` : "");
    if (window.location.hash !== url) window.location.hash = url;
    else onChange();
  }

  window.addEventListener("hashchange", onChange);

  return { add, go, start: onChange };
})();

/**
 * =========================
 * Section 10. UI primitives
 * =========================
 */

const Dom = {
  /** @param {string} tag @param {Record<string, any>=} props @param {(Node|string)[]=} children */
  el(tag, props, children) {
    const e = document.createElement(tag);
    if (props) for (const [k, v] of Object.entries(props)) {
      if (k === "class") e.className = String(v);
      else if (k === "dataset" && v && typeof v === "object") for (const [dk, dv] of Object.entries(v)) e.dataset[dk] = String(dv);
      else if (k.startsWith("on") && typeof v === "function") e.addEventListener(k.substring(2), v);
      else if (k === "text") e.textContent = String(v);
      else if (k === "attr" && v && typeof v === "object") for (const [ak, av] of Object.entries(v)) e.setAttribute(ak, String(av));
      else if (k === "aria" && v && typeof v === "object") for (const [ak, av] of Object.entries(v)) e.setAttribute(`aria-${ak}`, String(av));
      else if (v !== null && v !== undefined) e.setAttribute(k, String(v));
    }
    if (children) for (const c of children) e.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
    return e;
  },
  mount(root, node) { root.innerHTML = ""; root.appendChild(node); },
  safeText: (s) => document.createTextNode(String(s || "")),
};

const Banner = (() => {
  let el = null;
  function ensure() {
    if (el) return el;
    el = Dom.el("div", { class: "ov-banner", role: "status", aria: { live: "polite" } });
    Object.assign(el.style, {
      position: "fixed", left: "0", right: "0", top: "0", padding: "10px 16px",
      background: "#fff3cd", color: "#664d03", borderBottom: "1px solid #ffe69c", fontFamily: "sans-serif", zIndex: "9999", display: "none"
    });
    document.body.appendChild(el);
    return el;
  }
  function show(text, level = "info") {
    const n = ensure();
    n.textContent = String(text);
    n.style.display = "block";
    n.style.background = level === "warn" ? "#fff3cd" : level === "error" ? "#f8d7da" : "#cfe2ff";
    n.style.color = level === "warn" ? "#664d03" : level === "error" ? "#842029" : "#084298";
  }
  function hide() { if (el) el.style.display = "none"; }
  return { show, hide };
})();

/**
 * =========================
 * Section 11. Views
 * =========================
 */

const Views = (() => {
  const root = () => document.getElementById("app") || document.body;

  function Layout(children, title = "OblivionVault Admin") {
    document.title = title;
    const { user } = Store.getState();

    const header = Dom.el("header", { class: "ov-header" }, [
      Dom.el("div", { class: "ov-brand", text: "OblivionVault" }),
      Dom.el("nav", { class: "ov-nav" }, [
        NavLink("Dashboard", "/dashboard"),
        Auth.hasRole("admin") ? NavLink("Users", "/users") : Dom.safeText(""),
      ]),
      Dom.el("div", { class: "ov-user" }, [
        Dom.el("span", { class: "ov-user-name", text: user?.name || user?.sub || "Guest" }),
        user ? Dom.el("button", { class: "ov-btn", onClick: onLogout, text: "Logout" }) : Dom.safeText("")
      ]),
    ]);

    const main = Dom.el("main", { class: "ov-main" }, [children]);

    const container = Dom.el("div", { class: "ov-container" }, [header, main]);
    applyBaseStylesOnce();
    return container;
  }

  function NavLink(text, route) {
    return Dom.el("a", { href: `#${route}`, class: "ov-link", text });
  }

  async function onLogout(e) { e.preventDefault(); await Auth.logout(); }

  function Login() {
    document.title = "Login | OblivionVault";
    const form = Dom.el("form", { class: "ov-card", aria: { describedby: "login-help" } }, [
      Dom.el("h1", { text: "Sign in" }),
      Dom.el("label", { for: "login-username", text: "Username" }),
      Dom.el("input", { id: "login-username", type: "text", required: true, autocomplete: "username" }),
      Dom.el("label", { for: "login-password", text: "Password" }),
      Dom.el("input", { id: "login-password", type: "password", required: true, autocomplete: "current-password" }),
      Dom.el("p", { id: "login-help", class: "ov-help", text: "Use your admin account credentials." }),
      Dom.el("button", { type: "submit", class: "ov-btn", text: "Login" }),
    ]);
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const u = /** @type {HTMLInputElement} */(form.querySelector("#login-username")).value.trim();
      const p = /** @type {HTMLInputElement} */(form.querySelector("#login-password")).value;
      try {
        await Auth.login(u, p);
        Router.go(CONFIG.router.defaultRoute || "/dashboard");
      } catch (err) {
        Banner.show("Ошибка входа. Проверьте логин/пароль.", "error");
        Logger.warn("login_failed", { user: u, error: String(err) });
      }
    });
    Dom.mount(root(), Dom.el("div", { class: "ov-login" }, [form]));
  }

  async function Dashboard() {
    const wrap = Dom.el("div", { class: "ov-card" }, [
      Dom.el("h1", { text: "Dashboard" }),
      Dom.el("p", { text: "Состояние системы и быстрые действия." }),
    ]);

    // Example: fetch server health
    try {
      const health = await Api.get("/health", { idempotent: true });
      wrap.appendChild(Dom.el("pre", { class: "ov-pre", text: JSON.stringify(health, null, 2) }));
    } catch (err) {
      wrap.appendChild(Dom.el("p", { class: "ov-err", text: "Не удалось получить состояние API." }));
    }

    Dom.mount(root(), Layout(wrap, "Dashboard | OblivionVault"));
  }

  async function Users() {
    if (!Auth.hasRole("admin")) {
      Banner.show("Недостаточно прав для просмотра Users.", "warn");
      return Router.go("/dashboard");
    }
    const panel = Dom.el("div", { class: "ov-card" }, [
      Dom.el("h1", { text: "Users" }),
      Dom.el("p", { text: "Список пользователей (пример)." }),
    ]);

    try {
      const users = await Api.get("/admin/users?limit=50", { idempotent: true });
      const table = Dom.el("table", { class: "ov-table", attr: { role: "table" } }, [
        Dom.el("thead", {}, [
          Dom.el("tr", {}, [
            Dom.el("th", { text: "ID" }), Dom.el("th", { text: "Name" }), Dom.el("th", { text: "Roles" })
          ])
        ]),
        Dom.el("tbody", {}, (Array.isArray(users) ? users : []).map((u) =>
          Dom.el("tr", {}, [
            Dom.el("td", { text: String(u.id || u.sub || "") }),
            Dom.el("td", { text: String(u.name || "") }),
            Dom.el("td", { text: Array.isArray(u.roles) ? u.roles.join(", ") : "" }),
          ])
        ))
      ]);
      panel.appendChild(table);
    } catch (err) {
      panel.appendChild(Dom.el("p", { class: "ov-err", text: "Не удалось загрузить пользователей." }));
      Logger.warn("users_load_failed", { error: String(err) });
    }

    Dom.mount(root(), Layout(panel, "Users | OblivionVault"));
  }

  function NotFound() {
    Dom.mount(root(), Layout(
      Dom.el("div", { class: "ov-card" }, [ Dom.el("h1", { text: "404" }), Dom.el("p", { text: "Страница не найдена." }) ]),
      "404 | OblivionVault"
    ));
  }

  /** one-time base styles (scoped, minimal) */
  let baseStylesApplied = false;
  function applyBaseStylesOnce() {
    if (baseStylesApplied) return; baseStylesApplied = true;
    const css = `
      :root { --ov-bg:#0b0e13; --ov-card:#121822; --ov-text:#e5ecf4; --ov-muted:#95a3b3; --ov-primary:#4ea1ff; --ov-danger:#ff5c5c; --ov-border:#223047; }
      * { box-sizing: border-box; }
      body { margin:0; background:var(--ov-bg); color:var(--ov-text); font-family: Inter, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, "Apple Color Emoji", "Segoe UI Emoji"; }
      a { color: var(--ov-primary); text-decoration: none; }
      .ov-container { max-width: 1100px; margin: 0 auto; padding: 12px; }
      .ov-header { display:flex; align-items:center; justify-content: space-between; padding: 8px 0; }
      .ov-brand { font-weight: 700; letter-spacing: .3px; }
      .ov-nav a { margin-right: 16px; }
      .ov-user { display:flex; align-items:center; gap:8px; color:var(--ov-muted); }
      .ov-main { margin-top: 12px; }
      .ov-card { background: var(--ov-card); border:1px solid var(--ov-border); border-radius: 12px; padding: 16px; }
      .ov-login { display:flex; align-items:center; justify-content:center; min-height: 70vh; }
      .ov-card input { width: 100%; padding: 10px 12px; margin: 6px 0 12px; border-radius: 8px; border:1px solid var(--ov-border); background:#0e141d; color:var(--ov-text); }
      .ov-btn { padding: 10px 14px; border-radius: 10px; border:1px solid var(--ov-border); background:#173152; color:#e5ecf4; cursor:pointer; }
      .ov-btn:hover { background:#1f3f6b; }
      .ov-link { padding: 6px 8px; }
      .ov-help { color: var(--ov-muted); font-size: 13px; }
      .ov-pre { white-space: pre-wrap; word-break: break-word; background:#0e141d; padding:12px; border-radius:8px; border:1px solid var(--ov-border); }
      .ov-table { width:100%; border-collapse: collapse; margin-top: 12px; }
      .ov-table th, .ov-table td { text-align:left; border-bottom:1px solid var(--ov-border); padding: 8px 6px; }
      .ov-err { color: var(--ov-danger); }
      @media (max-width:640px){ .ov-header{flex-direction:column; align-items:flex-start;} .ov-user{align-self:flex-end;} }
    `;
    const style = Dom.el("style", { text: css });
    document.head.appendChild(style);
  }

  return { Login, Dashboard, Users, NotFound };
})();


/**
 * =========================
 * Section 12. RUM metrics
 * =========================
 */

const RUM = (() => {
  const enabled = Math.random() < (CONFIG.telemetry?.sampleRate || 0);
  function send(event, fields) {
    if (!enabled) return;
    try {
      const payload = JSON.stringify({
        ts: Date.now(),
        event,
        fields,
        service: CONFIG.service,
        env: CONFIG.env,
        sid: Logger.getContext().sessionId
      });
      if (navigator.sendBeacon) {
        navigator.sendBeacon(CONFIG.telemetry?.rumEndpoint || "/observability/rum", new Blob([payload], {type: "application/json"}));
      }
    } catch {}
  }
  function boot() {
    try {
      const nav = performance.getEntriesByType("navigation")[0];
      if (nav) {
        send("nav_timing", {
          domComplete: nav.domComplete, domInteractive: nav.domInteractive,
          loadEventEnd: nav.loadEventEnd, responseEnd: nav.responseEnd,
          type: nav.type
        });
      }
    } catch {}
  }
  return { send, boot };
})();


/**
 * =========================
 * Section 13. App bootstrap
 * =========================
 */

function guardAuthAndRoute() {
  const { path } = (function(){ const raw = window.location.hash.replace(/^#/, ""); const [p] = raw.split("?"); return { path: p || "/" }; })();
  const { accessToken } = Store.getState();
  const isLoginRoute = path === "/login" || path === "/";
  if (!accessToken && !isLoginRoute) return Router.go("/login");
  if (accessToken && isLoginRoute) return Router.go(CONFIG.router.defaultRoute || "/dashboard");
  return Router.start();
}

function registerRoutes() {
  Router.add("/", () => Views.Login());
  Router.add("/login", () => Views.Login());
  Router.add("/dashboard", () => Views.Dashboard());
  Router.add("/users", () => Views.Users());
  Router.add("/404", () => Views.NotFound());
}

function mountApp() {
  // Load persisted session
  Session.loadFromStorage();

  // Apply request id per navigation
  Logger.setRequestId(uuid4());

  // RUM boot
  RUM.boot();

  // Routes & initial navigation
  registerRoutes();
  guardAuthAndRoute();

  // Reactive rerender on auth state change (basic)
  Store.subscribe(() => guardAuthAndRoute());
}

// DOM ready
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", mountApp);
} else {
  mountApp();
}
