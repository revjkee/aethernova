/* eslint-disable no-console */
/**
 * admin-minimal/main.js
 * Цель: безопасный, минимальный, автономный админ‑клиент без фреймворков.
 * Требования окружения: современный браузер (ES2020+, fetch, crypto.subtle).
 *
 * ВНИМАНИЕ: Все DOM‑вставки проходят через safeHTML() чтобы снизить XSS‑риски.
 */

/* ===============================
 * Конфигурация
 * =============================== */

const CONFIG = Object.freeze({
  API_BASE_URL: window.__API_BASE_URL__ || "/api",
  OAUTH: {
    clientId: window.__OAUTH_CLIENT_ID__ || "admin-minimal",
    issuer: window.__OAUTH_ISSUER__ || "/oauth",
    redirectUri: window.location.origin + window.location.pathname,
    scope: "openid profile email offline_access",
    // PKCE:
    codeChallengeMethod: "S256",
  },
  REQUEST: {
    timeoutMs: 15000,
    maxRetries: 3,
    retryBaseMs: 300,
    retryJitterMs: 200,
  },
  FEATURES: {
    enableTelemetry: true,
    enableServiceWorker: true,
  },
  I18N: {
    defaultLocale: "en",
    supported: ["en", "ru"],
  },
});

/* ===============================
 * Утилиты безопасности и вспомогательные
 * =============================== */

const Text = document.createTextNode.bind(document);

/** Безопасная вставка HTML: используется шаблонная строка с заменами через Node */
function safeHTML(strings, ...values) {
  const frag = document.createDocumentFragment();
  strings.forEach((s, i) => {
    frag.appendChild(Text(s));
    if (i < values.length) {
      const v = values[i];
      if (v instanceof Node) {
        frag.appendChild(v);
      } else {
        frag.appendChild(Text(String(v)));
      }
    }
  });
  const div = document.createElement("div");
  div.appendChild(frag);
  return div.innerHTML;
}

function uuid4() {
  return ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, c =>
    (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16)
  );
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function nowIso() { return new Date().toISOString(); }

/** Генерация Idempotency-Key для мутаций */
function idempotencyKey() { return `ik_${uuid4()}`; }

/** W3C traceparent генерация (корреляция) */
function makeTraceparent() {
  const rand = crypto.getRandomValues(new Uint8Array(16));
  const traceId = [...rand].map(b => b.toString(16).padStart(2, "0")).join("");
  const spanId = traceId.slice(0, 16);
  return `00-${traceId}-${spanId}-01`;
}

/* ===============================
 * Простое локальное «хранилище» с in‑memory шифрованием (для токенов)
 * =============================== */

const MemoryVault = (() => {
  let key; // CryptoKey
  let cache = {};
  async function ensureKey() {
    if (!key) {
      key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
    }
    return key;
  }
  async function set(name, value) {
    const enc = new TextEncoder().encode(JSON.stringify(value));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const k = await ensureKey();
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, k, enc);
    cache[name] = { iv: Array.from(iv), ct: btoa(String.fromCharCode(...new Uint8Array(ct))) };
  }
  async function get(name) {
    const row = cache[name];
    if (!row) return null;
    const iv = new Uint8Array(row.iv);
    const ct = Uint8Array.from(atob(row.ct), c => c.charCodeAt(0));
    const k = await ensureKey();
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, k, ct);
    return JSON.parse(new TextDecoder().decode(new Uint8Array(pt)));
  }
  async function del(name) { delete cache[name]; }
  return { set, get, del };
})();

/* ===============================
 * i18n (минимум)
 * =============================== */

const LOCALES = {
  en: {
    login: "Sign in",
    logout: "Sign out",
    anchors: "Anchors",
    create: "Create",
    name: "Name",
    status: "Status",
    active: "active",
    inactive: "inactive",
    error_generic: "Unexpected error",
  },
  ru: {
    login: "Войти",
    logout: "Выйти",
    anchors: "Якоря",
    create: "Создать",
    name: "Имя",
    status: "Статус",
    active: "active",
    inactive: "inactive",
    error_generic: "Непредвиденная ошибка",
  },
};
function t(key) {
  const lang = (navigator.language || CONFIG.I18N.defaultLocale).slice(0,2);
  const locale = LOCALES[CONFIG.I18N.supported.includes(lang) ? lang : CONFIG.I18N.defaultLocale];
  return locale[key] || key;
}

/* ===============================
 * Тосты/уведомления
 * =============================== */

const Toasts = (() => {
  const root = document.createElement("div");
  root.style.cssText = "position:fixed;top:10px;right:10px;z-index:9999;font:14px system-ui, sans-serif;";
  document.addEventListener("DOMContentLoaded", () => document.body.appendChild(root));
  function show(msg, type = "info") {
    const el = document.createElement("div");
    el.style.cssText = `
      background:${type === "error" ? "#7f1d1d" : type === "success" ? "#065f46" : "#1e40af"};
      color:#fff;padding:10px 12px;margin:8px;border-radius:6px;box-shadow:0 2px 8px rgba(0,0,0,.2)`;
    el.textContent = msg;
    root.appendChild(el);
    setTimeout(() => el.remove(), 3500);
  }
  return { show };
})();

/* ===============================
 * API‑клиент с ретраями/таймаутами/идемпотентностью
 * =============================== */

class ApiClient {
  constructor({ baseUrl, getAccessToken, onUnauthorized }) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.getAccessToken = getAccessToken;
    this.onUnauthorized = onUnauthorized;
  }

  async request(path, { method = "GET", headers = {}, body = null, timeoutMs = CONFIG.REQUEST.timeoutMs, idempotent = false } = {}) {
    const url = `${this.baseUrl}${path}`;
    const abort = new AbortController();
    const timer = setTimeout(() => abort.abort("timeout"), timeoutMs);

    const token = await this.getAccessToken?.();
    const baseHeaders = {
      "Accept": "application/json",
      "Content-Type": body ? "application/json" : "application/json",
      "X-Request-ID": uuid4(),
      "Traceparent": makeTraceparent(),
    };
    if (token) baseHeaders["Authorization"] = `Bearer ${token}`;
    if (idempotent && ["POST","PUT","PATCH","DELETE"].includes(method)) {
      baseHeaders["Idempotency-Key"] = idempotencyKey();
    }

    const opts = {
      method,
      headers: { ...baseHeaders, ...headers },
      signal: abort.signal,
      body: body ? JSON.stringify(body) : null,
      credentials: "include",
    };

    let attempt = 0, lastErr;
    while (attempt <= CONFIG.REQUEST.maxRetries) {
      try {
        const resp = await fetch(url, opts);
        if (resp.status === 401) {
          await this.onUnauthorized?.();
          throw new Error("unauthorized");
        }
        if (!resp.ok) {
          // Попробуем прочитать унифицированную ошибку
          let err;
          try { err = await resp.json(); } catch { err = { message: resp.statusText }; }
          // ретраим только 5xx/429
          if ([429,500,502,503,504].includes(resp.status) && attempt < CONFIG.REQUEST.maxRetries) {
            attempt++;
            await this.#backoff(attempt);
            continue;
          }
          const e = new Error(err.message || `HTTP ${resp.status}`);
          e.payload = err;
          e.status = resp.status;
          throw e;
        }
        clearTimeout(timer);
        const ct = resp.headers.get("content-type") || "";
        return ct.includes("application/json") ? resp.json() : resp.text();
      } catch (e) {
        lastErr = e;
        if (e.name === "AbortError") {
          if (attempt < CONFIG.REQUEST.maxRetries) {
            attempt++;
            await this.#backoff(attempt);
            continue;
          }
          break;
        }
        // сеть/временный сбой
        if (attempt < CONFIG.REQUEST.maxRetries) {
          attempt++;
          await this.#backoff(attempt);
          continue;
        }
        break;
      } finally {
        clearTimeout(timer);
      }
    }
    throw lastErr || new Error("request failed");
  }

  async #backoff(attempt) {
    const base = CONFIG.REQUEST.retryBaseMs * Math.pow(2, attempt - 1);
    const jitter = Math.random() * CONFIG.REQUEST.retryJitterMs;
    await sleep(base + jitter);
  }

  // Удобные шорткаты
  get(path, opts) { return this.request(path, { ...opts, method: "GET" }); }
  post(path, body, opts) { return this.request(path, { ...opts, method: "POST", body, idempotent: true }); }
  put(path, body, opts) { return this.request(path, { ...opts, method: "PUT", body, idempotent: true }); }
  delete(path, opts) { return this.request(path, { ...opts, method: "DELETE", idempotent: true }); }
}

/* ===============================
 * OAuth2 PKCE (минимум) + refresh
 * =============================== */

const Auth = (() => {
  let tokenSet = null; // { access_token, refresh_token, exp }
  const storeName = "auth_token";

  async function load() {
    const row = await MemoryVault.get(storeName);
    if (row && row.access_token && row.refresh_token) {
      tokenSet = row;
    }
  }
  async function save() {
    await MemoryVault.set(storeName, tokenSet);
  }
  async function clear() {
    tokenSet = null;
    await MemoryVault.del(storeName);
  }
  function isExpiredAhead(sec = 30) {
    if (!tokenSet?.exp) return true;
    return (Date.now()/1000 + sec) >= tokenSet.exp;
  }

  async function refresh() {
    if (!tokenSet?.refresh_token) throw new Error("no refresh token");
    const resp = await fetch(`${CONFIG.OAUTH.issuer}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: tokenSet.refresh_token,
        client_id: CONFIG.OAUTH.clientId,
      }),
      credentials: "include",
    });
    if (!resp.ok) throw new Error(`refresh failed: ${resp.status}`);
    const data = await resp.json();
    tokenSet = {
      access_token: data.access_token,
      refresh_token: data.refresh_token || tokenSet.refresh_token,
      exp: Math.floor(Date.now()/1000) + (data.expires_in || 3600),
    };
    await save();
  }

  async function getAccessToken() {
    await load();
    if (!tokenSet) return null;
    if (isExpiredAhead()) {
      try { await refresh(); } catch { await clear(); return null; }
    }
    return tokenSet.access_token;
  }

  async function loginWithPassword(username, password) {
    // Только для «минимального» варианта. Для прод — PKCE‑код‑flow через redirect.
    const resp = await fetch(`${CONFIG.OAUTH.issuer}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "password",
        username, password,
        client_id: CONFIG.OAUTH.clientId,
        scope: CONFIG.OAUTH.scope,
      }),
      credentials: "include",
    });
    if (!resp.ok) throw new Error("invalid credentials");
    const data = await resp.json();
    tokenSet = {
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      exp: Math.floor(Date.now()/1000) + (data.expires_in || 3600),
    };
    await save();
    return true;
  }

  return { getAccessToken, loginWithPassword, clear };
})();

/* ===============================
 * Телеметрия (простая)
 * =============================== */

const Telemetry = (() => {
  const enabled = CONFIG.FEATURES.enableTelemetry;
  function evt(name, fields = {}) {
    if (!enabled) return;
    try {
      const rec = { name, ts: nowIso(), ...fields };
      // Для мини‑клиента отправляем fire‑and‑forget, без ожидания
      navigator.sendBeacon?.(`${CONFIG.API_BASE_URL}/telemetry/fe`, new Blob([JSON.stringify(rec)], { type: "application/json" }));
    } catch { /* ignore */ }
  }
  return { evt };
})();

/* ===============================
 * Роутер (hash‑routing)
 * =============================== */

const Router = (() => {
  const routes = {};
  function on(path, handler) { routes[path] = handler; }
  async function go(path) {
    if (location.hash !== `#${path}`) location.hash = `#${path}`;
    await render();
  }
  async function render() {
    const path = location.hash.slice(1) || "/anchors";
    const handler = routes[path] || routes["/404"];
    if (handler) await handler();
  }
  window.addEventListener("hashchange", render);
  return { on, go, render };
})();

/* ===============================
 * Вьюхи
 * =============================== */

const api = new ApiClient({
  baseUrl: CONFIG.API_BASE_URL,
  getAccessToken: Auth.getAccessToken,
  onUnauthorized: async () => {
    await Auth.clear();
    Toasts.show("Session expired", "error");
    Router.go("/login");
  },
});

function mount(el) {
  const root = document.getElementById("app") || document.body;
  root.innerHTML = "";
  root.appendChild(el);
}

function button(label, onClick, variant = "primary") {
  const b = document.createElement("button");
  b.type = "button";
  b.textContent = label;
  b.style.cssText = `
    background:${variant==="danger"?"#991b1b":variant==="secondary"?"#374151":"#1f2937"};
    color:#fff;border:none;border-radius:8px;padding:10px 14px;cursor:pointer;font:14px system-ui,sans-serif;margin:4px;`;
  b.addEventListener("click", onClick);
  return b;
}

function input(placeholder) {
  const i = document.createElement("input");
  i.placeholder = placeholder;
  i.style.cssText = "padding:10px;border-radius:8px;border:1px solid #d1d5db;margin:4px;font:14px system-ui,sans-serif;";
  return i;
}

/* ---- Login ---- */
Router.on("/login", async () => {
  const wrap = document.createElement("div");
  wrap.style.cssText = "max-width:420px;margin:5vh auto;padding:24px;border:1px solid #e5e7eb;border-radius:12px;font:14px system-ui,sans-serif;";
  const u = input("username");
  const p = input("password"); p.type="password";
  const submit = button(t("login"), async () => {
    try {
      await Auth.loginWithPassword(u.value, p.value);
      Telemetry.evt("login.success");
      Router.go("/anchors");
    } catch (e) {
      Telemetry.evt("login.error");
      Toasts.show("Invalid credentials", "error");
    }
  });
  wrap.innerHTML = safeHTML`
    <h2 style="margin:0 0 12px 0;">admin-minimal</h2>
  `;
  wrap.appendChild(u); wrap.appendChild(p); wrap.appendChild(submit);
  mount(wrap);
});

/* ---- Anchors list ---- */
Router.on("/anchors", async () => {
  const token = await Auth.getAccessToken();
  if (!token) return Router.go("/login");

  const container = document.createElement("div");
  container.style.cssText = "max-width:960px;margin:3vh auto;padding:16px;font:14px system-ui,sans-serif;";

  const title = document.createElement("div");
  title.style.cssText = "display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;";
  title.innerHTML = safeHTML`<h2 style="margin:0;">${t("anchors")}</h2>`;

  const btnCreate = button(t("create"), async () => {
    const name = prompt(`${t("name")}:`);
    if (!name) return;
    try {
      const created = await api.post("/v1/anchors", { name, status: "active" });
      Toasts.show("Created", "success");
      Telemetry.evt("anchor.created", { id: created.id });
      await Router.render();
    } catch (e) {
      console.error(e);
      Toasts.show(e?.payload?.message || t("error_generic"), "error");
    }
  });
  const btnLogout = button(t("logout"), async () => {
    await Auth.clear();
    Router.go("/login");
  },"secondary");
  const actionWrap = document.createElement("div");
  actionWrap.appendChild(btnCreate);
  actionWrap.appendChild(btnLogout);
  title.appendChild(actionWrap);

  const table = document.createElement("table");
  table.style.cssText = "width:100%;border-collapse:collapse;";
  table.innerHTML = safeHTML`
    <thead><tr>
      <th style="text-align:left;border-bottom:1px solid #e5e7eb;padding:8px;">ID</th>
      <th style="text-align:left;border-bottom:1px solid #e5e7eb;padding:8px;">${t("name")}</th>
      <th style="text-align:left;border-bottom:1px solid #e5e7eb;padding:8px;">${t("status")}</th>
      <th style="text-align:left;border-bottom:1px solid #e5e7eb;padding:8px;">ETag</th>
      <th style="text-align:left;border-bottom:1px solid #e5e7eb;padding:8px;">Actions</th>
    </tr></thead>
    <tbody></tbody>
  `;

  mount(container);
  container.appendChild(title);
  container.appendChild(table);

  // Fetch anchors
  try {
    const page = await api.get("/v1/anchors?limit=50");
    const tbody = table.querySelector("tbody");
    for (const a of page.data || []) {
      const tr = document.createElement("tr");
      tr.innerHTML = safeHTML`
        <td style="padding:8px;border-bottom:1px solid #f3f4f6;">${a.id}</td>
        <td style="padding:8px;border-bottom:1px solid #f3f4f6;">${a.name}</td>
        <td style="padding:8px;border-bottom:1px solid #f3f4f6;">${a.status}</td>
        <td style="padding:8px;border-bottom:1px solid #f3f4f6;">v${a.version}</td>
        <td style="padding:8px;border-bottom:1px solid #f3f4f6;"></td>
      `;
      const actions = document.createElement("div");
      actions.style.cssText = "display:flex;gap:6px;";
      const btnDeactivate = button("Toggle", async () => {
        const newStatus = a.status === "active" ? "inactive" : "active";
        try {
          await api.put(`/v1/anchors/${a.id}`, { name: a.name, status: newStatus }, { headers: { "If-Match": `"${a.version}"` } });
          Toasts.show("Updated", "success");
          await Router.render();
        } catch (e) {
          Toasts.show(e?.payload?.message || t("error_generic"), "error");
        }
      },"secondary");
      const btnDelete = button("Delete", async () => {
        if (!confirm("Delete anchor?")) return;
        try {
          await api.delete(`/v1/anchors/${a.id}`, { headers: { "If-Match": `"${a.version}"` } });
          Toasts.show("Deleted", "success");
          await Router.render();
        } catch (e) {
          Toasts.show(e?.payload?.message || t("error_generic"), "error");
        }
      },"danger");
      actions.appendChild(btnDeactivate);
      actions.appendChild(btnDelete);
      tr.lastElementChild.appendChild(actions);
      tbody.appendChild(tr);
    }
  } catch (e) {
    console.error(e);
    Toasts.show(e?.payload?.message || t("error_generic"), "error");
  }
});

/* ---- 404 ---- */
Router.on("/404", async () => {
  const div = document.createElement("div");
  div.style.cssText = "max-width:600px;margin:10vh auto;text-align:center;font:14px system-ui,sans-serif;";
  div.innerHTML = safeHTML`<h2>404</h2><p>Not found</p>`;
  mount(div);
});

/* ===============================
 * Bootstrap
 * =============================== */

(async function bootstrap() {
  // CSP runtime hint (не безопасность сама по себе, но даёт сигнал в логи)
  try {
    if (!("strict-dynamic" in (document.querySelector('meta[http-equiv="Content-Security-Policy"]')?.content || ""))) {
      console.warn("CSP meta tag is missing or not strict-dynamic");
    }
  } catch {}

  // Service Worker
  if ("serviceWorker" in navigator && CONFIG.FEATURES.enableServiceWorker) {
    try {
      await navigator.serviceWorker.register("./sw.js", { scope: "./" });
    } catch (e) { /* ignore */ }
  }

  // initial route
  await Router.render();
})();
