/* neuroforge-core/clients/web-admin-minimal/main.js
   Industrial-grade minimal Web Admin bootstrap (no external deps).
   Usage: <script type="module" src="/clients/web-admin-minimal/main.js"></script>
   Requires: a root container <div id="app"></div> in HTML.

   Security notes:
   - Enforce CSP on server (default-src 'self'; script-src 'self'; connect-src 'self' https:; img-src 'self' data:; style-src 'self' 'unsafe-inline' if needed).
   - All external links use rel="noopener noreferrer" automatically.
   - Sanitizer strips dangerous HTML. Do not render untrusted HTML without it.
*/

"use strict";

// -----------------------------
// 0) Tiny module system via ESM sections (plain file)
// -----------------------------

// 1) CONFIG ---------------------------------------------------------------
const Config = (() => {
  // Config is resolved from window.__APP_CONFIG__ or meta tags.
  const meta = (name, fallback = "") => {
    const el = document.querySelector(`meta[name="${name}"]`);
    return el?.getAttribute("content") || fallback;
  };

  const runtime = /** @type {any} */ (window).__APP_CONFIG__ || {};
  const env = {
    ENV: runtime.ENV || meta("env", "dev"),
    SERVICE: runtime.SERVICE || meta("service", "web-admin"),
    VERSION: runtime.VERSION || meta("version", "0.0.1"),
    API_BASE: runtime.API_BASE || meta("api-base", "/api"),
    TELEMETRY_URL: runtime.TELEMETRY_URL || meta("telemetry-url", "/telemetry"),
    AUTH_REFRESH_PATH: runtime.AUTH_REFRESH_PATH || "/auth/refresh",
    AUTH_LOGIN_PATH: runtime.AUTH_LOGIN_PATH || "/auth/login",
    FLAG_SOURCE: runtime.FLAG_SOURCE || meta("flag-source", ""),
    USE_HISTORY_ROUTER: runtime.USE_HISTORY_ROUTER ?? true,
    REQUEST_TIMEOUT_MS: Number(runtime.REQUEST_TIMEOUT_MS || 15000),
    RETRY_MAX_ATTEMPTS: Number(runtime.RETRY_MAX_ATTEMPTS || 3),
    RETRY_BASE_DELAY_MS: Number(runtime.RETRY_BASE_DELAY_MS || 250),
    OFFLINE_QUEUE_MAX: Number(runtime.OFFLINE_QUEUE_MAX || 100),
    LOG_LEVEL: runtime.LOG_LEVEL || meta("log-level", "INFO"),
    CAPTURE_WEB_VITALS: runtime.CAPTURE_WEB_VITALS ?? true,
  };

  return Object.freeze(env);
})();

// 2) LOGGER ---------------------------------------------------------------
const Logger = (() => {
  const LEVELS = { DEBUG: 10, INFO: 20, WARN: 30, ERROR: 40, SILENT: 99 };
  let currentLevel = LEVELS[String(Config.LOG_LEVEL).toUpperCase()] ?? LEVELS.INFO;

  const redact = (v) => {
    if (typeof v === "string") {
      // Basic PII redaction
      v = v.replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, "[REDACTED]");
      v = v.replace(/(?:\+?\d[\s\-()]*){7,}\d/g, "[REDACTED]");
      v = v.replace(/\b(?:\d[ -]*?){13,19}\b/g, "[REDACTED]");
      v = v.replace(/(?i)(api[_-]?key|secret|token)\s*[:=]\s*[\w\-\.~\+\/]+=*/gi, "[REDACTED]");
      return v;
    }
    if (v && typeof v === "object") {
      const clone = Array.isArray(v) ? [] : {};
      for (const k in v) clone[k] = redact(v[k]);
      return clone;
    }
    return v;
  };

  const fmt = (level, msg, meta) => ({
    ts: new Date().toISOString(),
    level,
    service: Config.SERVICE,
    env: Config.ENV,
    version: Config.VERSION,
    msg: typeof msg === "string" ? redact(msg) : JSON.stringify(redact(msg)),
    meta: redact(meta || {}),
  });

  const sinkConsole = (payload) => {
    const { level, msg, meta } = payload;
    // eslint-disable-next-line no-console
    if (level === "ERROR") console.error(msg, meta);
    else if (level === "WARN") console.warn(msg, meta);
    else if (level === "INFO") console.info(msg, meta);
    else console.debug(msg, meta);
  };

  // Remote sink with backoff batching
  const queue = [];
  let flushing = false;
  const enqueue = (payload) => {
    queue.push(payload);
    if (!flushing) flushSoon();
  };
  const flushSoon = () => setTimeout(flush, 400);
  async function flush() {
    if (flushing || queue.length === 0 || !Config.TELEMETRY_URL) return;
    flushing = true;
    const batch = queue.splice(0, Math.min(queue.length, 50));
    try {
      await fetch(Config.TELEMETRY_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        keepalive: true,
        body: JSON.stringify({ type: "log", entries: batch }),
      });
    } catch (_) {
      // on failure, drop to avoid infinite growth (logs must not break app)
    } finally {
      flushing = false;
    }
  }

  const log = (lvl, msg, meta) => {
    if (LEVELS[lvl] < currentLevel) return;
    const payload = fmt(lvl, msg, meta);
    sinkConsole(payload);
    enqueue(payload);
  };

  return Object.freeze({
    setLevel: (name) => {
      currentLevel = LEVELS[String(name).toUpperCase()] ?? currentLevel;
    },
    debug: (m, meta) => log("DEBUG", m, meta),
    info: (m, meta) => log("INFO", m, meta),
    warn: (m, meta) => log("WARN", m, meta),
    error: (m, meta) => log("ERROR", m, meta),
  });
})();

// 3) STORE (safe local/session) ------------------------------------------
const Store = (() => {
  const prefix = `${Config.SERVICE}:${Config.ENV}:`;
  const safe = (op, ...args) => {
    try { return op(...args); } catch (_) { return null; }
  };
  const j = {
    get: (k) => {
      const raw = safe(() => localStorage.getItem(prefix + k));
      if (!raw) return null;
      try { return JSON.parse(raw); } catch { return null; }
    },
    set: (k, v) => safe(() => localStorage.setItem(prefix + k, JSON.stringify(v))),
    del: (k) => safe(() => localStorage.removeItem(prefix + k)),
  };
  const s = {
    get: (k) => {
      const raw = safe(() => sessionStorage.getItem(prefix + k));
      if (!raw) return null;
      try { return JSON.parse(raw); } catch { return null; }
    },
    set: (k, v) => safe(() => sessionStorage.setItem(prefix + k, JSON.stringify(v))),
    del: (k) => safe(() => sessionStorage.removeItem(prefix + k)),
  };
  return Object.freeze({ j, s });
})();

// 4) EVENT BUS -----------------------------------------------------------
const Bus = (() => {
  const t = new Map();
  return Object.freeze({
    on(ev, cb) {
      const arr = t.get(ev) || [];
      arr.push(cb);
      t.set(ev, arr);
      return () => this.off(ev, cb);
    },
    off(ev, cb) {
      const arr = t.get(ev) || [];
      const i = arr.indexOf(cb);
      if (i >= 0) arr.splice(i, 1);
      t.set(ev, arr);
    },
    emit(ev, payload) {
      const arr = t.get(ev) || [];
      for (const cb of arr.slice()) {
        try { cb(payload); } catch (e) { Logger.error("Bus handler error", { ev, e }); }
      }
    },
  });
})();

// 5) I18N ----------------------------------------------------------------
const I18N = (() => {
  const dict = {
    en: {
      app_title: "NeuroForge Admin",
      login: "Login",
      logout: "Log out",
      email: "Email",
      password: "Password",
      sign_in: "Sign in",
      dashboard: "Dashboard",
      users: "Users",
      loading: "Loading...",
      network_offline: "You are offline. Changes will be queued.",
      network_online: "Back online. Syncing queued actions...",
      error_generic: "Unexpected error. Please try again.",
    },
    ru: {
      app_title: "NeuroForge Админка",
      login: "Вход",
      logout: "Выход",
      email: "Email",
      password: "Пароль",
      sign_in: "Войти",
      dashboard: "Панель",
      users: "Пользователи",
      loading: "Загрузка...",
      network_offline: "Вы офлайн. Изменения будут поставлены в очередь.",
      network_online: "Снова онлайн. Синхронизация очереди...",
      error_generic: "Неожиданная ошибка. Повторите попытку.",
    },
  };
  const lang = (navigator.language || "en").split("-")[0];
  let current = dict[lang] ? lang : "en";
  const t = (key, vars = {}) => {
    const base = dict[current][key] ?? key;
    return base.replace(/\{(\w+)\}/g, (_, k) => String(vars[k] ?? ""));
  };
  const set = (lng) => { if (dict[lng]) current = lng; };
  return Object.freeze({ t, set, get lang() { return current; } });
})();

// 6) FLAGS ---------------------------------------------------------------
const Flags = (() => {
  let cache = {};
  async function load() {
    if (!Config.FLAG_SOURCE) return cache;
    try {
      const res = await fetch(Config.FLAG_SOURCE, { cache: "no-store" });
      if (res.ok) cache = await res.json();
    } catch (e) { Logger.warn("Failed to load flags", { e }); }
    return cache;
  }
  const isOn = (k, def = false) => cache[k] ?? def;
  return Object.freeze({ load, isOn });
})();

// 7) SANITIZER & DOM UTILS -----------------------------------------------
const Dom = (() => {
  const sanitize = (html) => {
    const t = document.createElement("template");
    t.innerHTML = String(html);
    // Remove scripts/iframse/events
    const walker = (node) => {
      if (node.nodeType === 1) {
        const el = /** @type {Element} */ (node);
        const tag = el.tagName.toLowerCase();
        if (["script", "iframe", "object", "embed", "link", "style"].includes(tag)) {
          el.remove();
          return;
        }
        // remove event handlers
        [...el.attributes].forEach((a) => {
          if (a.name.startsWith("on")) el.removeAttribute(a.name);
          if (a.name === "href" && el.getAttribute("href")?.startsWith("javascript:")) el.removeAttribute("href");
        });
        [...el.children].forEach(walker);
      }
    };
    [...t.content.childNodes].forEach(walker);
    return t.innerHTML;
  };

  const safeHTML = (root, html) => { root.innerHTML = sanitize(html); };
  const text = (root, s) => { root.textContent = String(s); };
  const a11yAnnounce = (msg) => {
    let live = document.getElementById("sr-live");
    if (!live) {
      live = document.createElement("div");
      live.id = "sr-live";
      live.setAttribute("role", "status");
      live.setAttribute("aria-live", "polite");
      live.style.position = "absolute"; live.style.width = "1px"; live.style.height = "1px"; live.style.overflow = "hidden"; live.style.clip = "rect(1px,1px,1px,1px)";
      document.body.appendChild(live);
    }
    live.textContent = msg;
  };

  const protectExternalLinks = () => {
    document.body.addEventListener("click", (e) => {
      const a = /** @type {HTMLElement} */ (e.target).closest?.("a[target=_blank]");
      if (a) {
        a.setAttribute("rel", "noopener noreferrer");
      }
    });
  };

  return Object.freeze({ sanitize, safeHTML, text, a11yAnnounce, protectExternalLinks });
})();

// 8) HTTP CLIENT (auth, retry, timeout) ----------------------------------
const Http = (() => {
  let accessToken = Store.j.get("auth.accessToken");
  let refreshToken = Store.j.get("auth.refreshToken");
  let refreshing = null;

  const setTokens = (at, rt) => {
    accessToken = at; refreshToken = rt;
    Store.j.set("auth.accessToken", at);
    Store.j.set("auth.refreshToken", rt);
  };
  const clearTokens = () => {
    accessToken = null; refreshToken = null;
    Store.j.del("auth.accessToken"); Store.j.del("auth.refreshToken");
  };

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  async function doFetch(url, opts, attempt = 0) {
    const ctrl = new AbortController();
    const to = setTimeout(() => ctrl.abort(), Config.REQUEST_TIMEOUT_MS);
    try {
      const headers = new Headers(opts.headers || {});
      headers.set("Accept", "application/json");
      if (!headers.has("Content-Type") && opts.body) headers.set("Content-Type", "application/json");
      if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
      const res = await fetch(url, { ...opts, headers, signal: ctrl.signal, credentials: "include" });
      if (res.status === 401 && refreshToken) {
        const ok = await ensureRefreshed();
        if (ok) return doFetch(url, opts, attempt + 1);
        // fallthrough: will be handled below
      }
      if (!res.ok) {
        // Retry only idempotent methods
        if (["GET", "HEAD"].includes((opts.method || "GET").toUpperCase()) && attempt + 1 < Config.RETRY_MAX_ATTEMPTS && res.status >= 500) {
          const delay = (2 ** attempt) * Config.RETRY_BASE_DELAY_MS;
          await sleep(delay);
          return doFetch(url, opts, attempt + 1);
        }
      }
      return res;
    } catch (e) {
      if (attempt + 1 < Config.RETRY_MAX_ATTEMPTS) {
        const delay = (2 ** attempt) * Config.RETRY_BASE_DELAY_MS;
        await sleep(delay);
        return doFetch(url, opts, attempt + 1);
      }
      throw e;
    } finally {
      clearTimeout(to);
    }
  }

  async function ensureRefreshed() {
    if (!refreshToken) return false;
    if (!refreshing) {
      refreshing = (async () => {
        try {
          const res = await fetch(Config.API_BASE + Config.AUTH_REFRESH_PATH, {
            method: "POST",
            headers: { "Content-Type": "application/json", Accept: "application/json" },
            credentials: "include",
            body: JSON.stringify({ refresh_token: refreshToken }),
          });
          if (!res.ok) throw new Error("refresh_failed");
          const data = await res.json();
          setTokens(data.access_token, data.refresh_token || refreshToken);
          Logger.info("Token refreshed");
          return true;
        } catch (e) {
          Logger.warn("Token refresh failed", { e });
          clearTokens();
          Bus.emit("auth:logout");
          return false;
        } finally {
          refreshing = null;
        }
      })();
    }
    return refreshing;
  }

  const json = async (path, opts = {}) => {
    const url = path.startsWith("http") ? path : Config.API_BASE + path;
    const res = await doFetch(url, opts);
    const ct = res.headers.get("Content-Type") || "";
    if (ct.includes("application/json")) {
      const data = await res.json();
      if (!res.ok) throw Object.assign(new Error("HTTP " + res.status), { status: res.status, data });
      return data;
    } else {
      const txt = await res.text();
      if (!res.ok) throw Object.assign(new Error("HTTP " + res.status), { status: res.status, data: txt });
      return txt;
    }
  };

  // Offline queue for mutations
  const queue = Store.j.get("offline.queue") || [];
  function enqueueMutation(req) {
    queue.push(req);
    if (queue.length > Config.OFFLINE_QUEUE_MAX) queue.shift();
    Store.j.set("offline.queue", queue);
    Logger.info("Enqueued offline action", { size: queue.length });
  }
  async function flushQueue() {
    while (queue.length) {
      const req = queue[0];
      try {
        await json(req.path, req.opts);
        queue.shift();
        Store.j.set("offline.queue", queue);
      } catch (e) {
        // stop on first failure
        break;
      }
    }
  }

  window.addEventListener("online", () => {
    Dom.a11yAnnounce(I18N.t("network_online"));
    flushQueue().catch(() => {});
  });
  window.addEventListener("offline", () => {
    Dom.a11yAnnounce(I18N.t("network_offline"));
  });

  const API = {
    get: (p, q) => json(p + (q ? "?" + new URLSearchParams(q) : ""), { method: "GET" }),
    post: (p, body) => navigator.onLine
      ? json(p, { method: "POST", body: JSON.stringify(body) })
      : (enqueueMutation({ path: p, opts: { method: "POST", body: JSON.stringify(body) } }), Promise.resolve({ queued: true })),
    put: (p, body) => navigator.onLine
      ? json(p, { method: "PUT", body: JSON.stringify(body) })
      : (enqueueMutation({ path: p, opts: { method: "PUT", body: JSON.stringify(body) } }), Promise.resolve({ queued: true })),
    del: (p) => navigator.onLine
      ? json(p, { method: "DELETE" })
      : (enqueueMutation({ path: p, opts: { method: "DELETE" } }), Promise.resolve({ queued: true })),
    auth: {
      login: async (email, password) => {
        const data = await json(Config.API_BASE + Config.AUTH_LOGIN_PATH, {
          method: "POST",
          body: JSON.stringify({ email, password }),
        });
        setTokens(data.access_token, data.refresh_token);
        Bus.emit("auth:login", data);
        return data;
      },
      logout: () => {
        clearTokens();
        Bus.emit("auth:logout");
      },
      tokens: () => ({ accessToken, refreshToken }),
    },
  };

  return Object.freeze(API);
})();

// 9) TELEMETRY -----------------------------------------------------------
const Telemetry = (() => {
  const buf = [];
  let pending = false;
  const push = (type, payload) => {
    buf.push({ ts: Date.now(), type, payload });
    if (!pending) setTimeout(flush, 1000);
  };
  async function flush() {
    if (pending || buf.length === 0 || !Config.TELEMETRY_URL) return;
    pending = true;
    const batch = buf.splice(0, Math.min(60, buf.length));
    try {
      await fetch(Config.TELEMETRY_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        keepalive: true,
        body: JSON.stringify({ type: "metrics", entries: batch }),
      });
    } catch (_) {
      // drop silently
    } finally {
      pending = false;
    }
  }

  // Web Perf
  function init() {
    if (!Config.CAPTURE_WEB_VITALS) return;
    try {
      const obs = new PerformanceObserver((list) => {
        for (const e of list.getEntries()) {
          push("perf", {
            name: e.name, entryType: e.entryType, startTime: Math.round(e.startTime), duration: Math.round(e.duration),
          });
        }
      });
      obs.observe({ entryTypes: ["navigation", "resource", "longtask"] });
    } catch (e) {
      Logger.debug("PerformanceObserver not available", { e });
    }
  }

  return Object.freeze({ push, init });
})();

// 10) ROUTER -------------------------------------------------------------
const Router = (() => {
  const routes = new Map();

  function add(path, handler) { routes.set(path, handler); return Router; }

  function match(path) {
    // Simple static or param /users/:id
    for (const [p, h] of routes) {
      if (p === path) return { handler: h, params: {} };
      const m = p.match(/^\/([\w-]+)\/:([\w-]+)$/);
      if (m) {
        const base = "/" + m[1];
        if (path.startsWith(base + "/")) {
          const rest = path.slice(base.length + 1);
          return { handler: h, params: { [m[2]]: decodeURIComponent(rest) } };
        }
      }
    }
    return null;
  }

  function go(path) {
    if (Config.USE_HISTORY_ROUTER) {
      history.pushState({}, "", path);
      render();
    } else {
      location.hash = "#" + path;
    }
  }

  async function render() {
    const path = Config.USE_HISTORY_ROUTER ? location.pathname : (location.hash.slice(1) || "/");
    const found = match(path) || match("/404");
    if (!found) return;
    try {
      await found.handler(found.params || {});
    } catch (e) {
      Logger.error("Route render error", { e, path });
      Views.renderError(I18N.t("error_generic"));
    }
  }

  function init() {
    if (Config.USE_HISTORY_ROUTER) {
      window.addEventListener("popstate", render);
    } else {
      window.addEventListener("hashchange", render);
    }
    return render();
  }

  return Object.freeze({ add, go, init, render });
})();

// 11) VIEWS --------------------------------------------------------------
const Views = (() => {
  const root = () => document.getElementById("app");

  function frame(title, content, opts = {}) {
    const logoutBtn = opts.showLogout
      ? `<button id="btn-logout" class="btn btn-secondary" aria-label="${I18N.t("logout")}">${I18N.t("logout")}</button>`
      : "";
    const nav = `
      <nav class="nav">
        <a href="/" data-link>🏠 ${I18N.t("dashboard")}</a>
        <a href="/users" data-link>${I18N.t("users")}</a>
        ${logoutBtn}
      </nav>
    `;
    const tpl = `
      <header class="header">
        <h1>${I18N.t("app_title")}</h1>
      </header>
      ${nav}
      <main id="main" tabindex="-1">${content}</main>
    `;
    Dom.safeHTML(root(), tpl);
    // intercept internal links
    root().querySelectorAll("[data-link]").forEach((a) => {
      a.addEventListener("click", (e) => {
        e.preventDefault();
        Router.go(a.getAttribute("href"));
      });
    });
    // logout
    const btnLogout = document.getElementById("btn-logout");
    if (btnLogout) btnLogout.onclick = () => Http.auth.logout();
    // focus main for a11y
    document.getElementById("main").focus();
  }

  function renderLogin() {
    const tpl = `
      <section class="auth">
        <h2>${I18N.t("login")}</h2>
        <form id="login-form" novalidate>
          <label>
            ${I18N.t("email")}
            <input type="email" id="email" autocomplete="username" required />
          </label>
          <label>
            ${I18N.t("password")}
            <input type="password" id="password" autocomplete="current-password" required />
          </label>
          <button id="submit" type="submit" class="btn btn-primary">${I18N.t("sign_in")}</button>
        </form>
      </section>
    `;
    frame(I18N.t("login"), tpl, { showLogout: false });
    const form = document.getElementById("login-form");
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const email = /** @type {HTMLInputElement} */(document.getElementById("email")).value.trim();
      const password = /** @type {HTMLInputElement} */(document.getElementById("password")).value;
      try {
        await Http.auth.login(email, password);
        Router.go("/");
      } catch (err) {
        Logger.warn("Login failed", { err });
        alert("Login failed");
      }
    });
  }

  function renderDashboard() {
    const tpl = `
      <section class="dash">
        <h2>${I18N.t("dashboard")}</h2>
        <div id="stats">${I18N.t("loading")}</div>
      </section>
    `;
    frame(I18N.t("dashboard"), tpl, { showLogout: true });
    (async () => {
      try {
        const data = await Http.get("/admin/stats");
        const html = `
          <ul>
            <li>Users: <strong>${Number(data.users ?? 0)}</strong></li>
            <li>Jobs: <strong>${Number(data.jobs ?? 0)}</strong></li>
            <li>Uptime: <strong>${String(data.uptime ?? "-")}</strong></li>
          </ul>
        `;
        Dom.safeHTML(document.getElementById("stats"), html);
      } catch (e) {
        Logger.error("Stats load failed", { e });
        Dom.text(document.getElementById("stats"), I18N.t("error_generic"));
      }
    })();
  }

  function renderUsers() {
    const tpl = `
      <section class="users">
        <h2>${I18N.t("users")}</h2>
        <div>
          <form id="user-create" class="row" novalidate>
            <input type="text" id="u-email" placeholder="email" required />
            <button type="submit" class="btn">Create</button>
          </form>
        </div>
        <div id="user-list">${I18N.t("loading")}</div>
      </section>
    `;
    frame(I18N.t("users"), tpl, { showLogout: true });

    const list = document.getElementById("user-list");
    const form = document.getElementById("user-create");
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const email = /** @type {HTMLInputElement} */(document.getElementById("u-email")).value.trim();
      try {
        await Http.post("/admin/users", { email });
        await loadUsers();
      } catch (err) {
        Logger.error("User create failed", { err });
        alert("Create failed");
      }
    });

    async function loadUsers() {
      try {
        const rows = await Http.get("/admin/users");
        const html = `
          <table class="table">
            <thead><tr><th>ID</th><th>Email</th><th>Actions</th></tr></thead>
            <tbody>
              ${rows.map((u) => `
                <tr>
                  <td>${String(u.id)}</td>
                  <td>${String(u.email)}</td>
                  <td><button class="btn btn-danger" data-id="${String(u.id)}">Delete</button></td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        `;
        Dom.safeHTML(list, html);
        list.querySelectorAll("button.btn-danger").forEach((btn) => {
          btn.addEventListener("click", async () => {
            const id = btn.getAttribute("data-id");
            try {
              await Http.del(`/admin/users/${encodeURIComponent(id)}`);
              await loadUsers();
            } catch (e) {
              Logger.error("User delete failed", { e });
              alert("Delete failed");
            }
          });
        });
      } catch (e) {
        Logger.error("Users load failed", { e });
        Dom.text(list, I18N.t("error_generic"));
      }
    }

    loadUsers();
  }

  function renderError(msg) {
    const tpl = `<section class="error"><h2>Error</h2><p>${Dom.sanitize(msg)}</p></section>`;
    frame("Error", tpl, { showLogout: true });
  }

  return Object.freeze({ renderLogin, renderDashboard, renderUsers, renderError });
})();

// 12) APP BOOT -----------------------------------------------------------
const App = (() => {
  function shortcuts() {
    window.addEventListener("keydown", (e) => {
      // Alt+D -> dashboard
      if (e.altKey && e.key.toLowerCase() === "d") { e.preventDefault(); Router.go("/"); }
      // Alt+U -> users
      if (e.altKey && e.key.toLowerCase() === "u") { e.preventDefault(); Router.go("/users"); }
    });
  }

  function guardAuth(to) {
    const { accessToken } = Http.auth.tokens();
    if (!accessToken && to !== "/login") {
      Router.go("/login");
      return false;
    }
    return true;
  }

  function registerSW() {
    if ("serviceWorker" in navigator) {
      navigator.serviceWorker.register("/sw.js").catch((e) => Logger.warn("SW register failed", { e }));
    }
  }

  function mountRouter() {
    Router
      .add("/login", () => Views.renderLogin())
      .add("/", () => guardAuth("/") && Views.renderDashboard())
      .add("/users", () => guardAuth("/users") && Views.renderUsers())
      .add("/404", () => Views.renderError("Not found"));

    Router.init();
  }

  function globalErrorHandlers() {
    window.addEventListener("error", (e) => {
      Logger.error("Global error", { message: e.message, stack: e.error?.stack });
      Telemetry.push("error", { message: e.message });
    });
    window.addEventListener("unhandledrejection", (e) => {
      Logger.error("Unhandled promise rejection", { reason: String(e.reason) });
      Telemetry.push("error", { reason: String(e.reason) });
    });
  }

  async function init() {
    Logger.info("Booting Web Admin", { env: Config.ENV, version: Config.VERSION });
    Dom.protectExternalLinks();
    Telemetry.init();
    globalErrorHandlers();
    shortcuts();
    await Flags.load();
    registerSW();
    mountRouter();

    Bus.on("auth:logout", () => Router.go("/login"));
  }

  return Object.freeze({ init });
})();

// 13) START --------------------------------------------------------------
document.addEventListener("DOMContentLoaded", () => {
  App.init().catch((e) => {
    Logger.error("Bootstrap failed", { e });
    const root = document.getElementById("app");
    if (root) root.textContent = "Bootstrap failed.";
  });
});
