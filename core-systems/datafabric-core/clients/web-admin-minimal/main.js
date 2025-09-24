/**
 * DataFabric Web Admin Minimal — main.js
 * Производственный, самодостаточный SPA без зависимостей.
 * Особенности:
 * - APIClient с retry (экспоненциальный backoff + jitter), таймаутом, отменой, refresh токена, CSRF.
 * - RBAC: роли из JWT/профиля. Маршруты с guard.
 * - Hash-роутер, lazy-вьюхи, централизованный Store (pub/sub), offline-детектор.
 * - UI-компоненты: таблица с пагинацией/сортировкой, тосты, модалки, спиннер, формы.
 * - Безопасность: строгий санитайзер для HTML, CSP-дружественно (никаких inline-скриптов), Esc ключи.
 * - Телеметрия: Web Vitals light, performance marks, отчеты об ошибках (window.onerror/unhandledrejection).
 * - Интеграции: health, jobs, lineage, consent, kms, settings.
 *
 * Требования к HTML:
 *   <meta name="df-api-base" content="/api">
 *   <meta name="df-csrf-header" content="X-CSRF-Token">
 *   <meta name="df-csrf-token" content="...">  (если требуется)
 *   <div id="app"></div>
 *
 * Рекомендуемая CSP:
 *   default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:;
 */

/* =========================================
 *  Utils: DOM, formatters, sanitizer
 * ========================================= */

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
const el = (tag, attrs = {}, children = []) => {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") node.className = v;
    else if (k === "dataset") Object.assign(node.dataset, v);
    else if (k.startsWith("on") && typeof v === "function") node.addEventListener(k.slice(2), v);
    else if (v !== undefined && v !== null) node.setAttribute(k, String(v));
  }
  for (const c of [].concat(children)) {
    if (c == null) continue;
    if (typeof c === "string") node.appendChild(document.createTextNode(c));
    else node.appendChild(c);
  }
  return node;
};

const bytesFmt = n => {
  if (n == null || isNaN(n)) return "-";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0, x = Number(n);
  while (x >= 1024 && i < u.length - 1) { x /= 1024; i++; }
  return `${x.toFixed(x >= 10 || i === 0 ? 0 : 1)} ${u[i]}`;
};
const dateFmt = iso => {
  if (!iso) return "-";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleString();
};

// Простой XSS‑санитайзер: удаляем теги, разрешаем безопасный текст.
const sanitize = (str) => {
  if (str == null) return "";
  const div = document.createElement("div");
  div.textContent = String(str);
  return div.innerHTML;
};

/* =========================================
 *  Config
 * ========================================= */
const cfg = (() => {
  const meta = n => document.querySelector(`meta[name="${n}"]`)?.getAttribute("content") || "";
  return {
    apiBase: meta("df-api-base") || "/api",
    csrfHeader: meta("df-csrf-header") || "X-CSRF-Token",
    csrfToken: meta("df-csrf-token") || "",
    requestTimeoutMs: 15000,
    retry: { attempts: 3, baseMs: 300, jitterMs: 200 },
    appTitle: "DataFabric Admin",
    version: "0.1.0",
  };
})();

/* =========================================
 *  Store (pub/sub)
 * ========================================= */
const Store = (() => {
  let state = {
    auth: { token: null, refreshToken: null, profile: null },
    online: navigator.onLine,
    toasts: [],
  };
  const subs = new Set();

  const get = () => state;
  const set = (patch) => {
    state = { ...state, ...patch };
    for (const cb of subs) try { cb(state); } catch {}
  };
  const subscribe = (cb) => { subs.add(cb); return () => subs.delete(cb); };
  return { get, set, subscribe };
})();

/* =========================================
 *  API Client with retry/timeout/auth
 * ========================================= */
class APIClient {
  constructor(base, { timeoutMs, retry, csrfHeader, csrfToken } = {}) {
    this.base = base.replace(/\/+$/, "");
    this.timeoutMs = timeoutMs || 15000;
    this.retry = retry || { attempts: 3, baseMs: 300, jitterMs: 200 };
    this.csrfHeader = csrfHeader;
    this.csrfToken = csrfToken;
  }

  _authHeaders() {
    const { auth } = Store.get();
    const h = {};
    if (auth?.token) h["Authorization"] = `Bearer ${auth.token}`;
    if (this.csrfToken) h[this.csrfHeader] = this.csrfToken;
    return h;
  }

  async fetch(path, { method = "GET", headers = {}, body, signal, retry = this.retry } = {}) {
    const url = path.startsWith("http") ? path : `${this.base}${path}`;
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort("timeout"), this.timeoutMs);
    const mergedSignal = signal ? anySignal([signal, controller.signal]) : controller.signal;
    const attempt = async (i) => {
      try {
        const res = await fetch(url, {
          method,
          headers: {
            "Accept": "application/json",
            ...(body && !(body instanceof FormData) ? { "Content-Type": "application/json" } : {}),
            ...this._authHeaders(),
            ...headers,
          },
          body: body && !(body instanceof FormData) ? JSON.stringify(body) : body,
          signal: mergedSignal
        });
        if (res.status === 401 && await this._tryRefresh()) {
          // Повтор после refresh
          return attempt(i);
        }
        if (!res.ok) {
          const text = await safeText(res);
          throw new HTTPError(res.status, text || res.statusText);
        }
        const ct = res.headers.get("content-type") || "";
        return ct.includes("application/json") ? await res.json() : await res.text();
      } catch (e) {
        if (e.name === "AbortError") throw e;
        if (i >= retry.attempts) throw e;
        const wait = backoff(i, retry.baseMs, retry.jitterMs);
        await sleep(wait);
        return attempt(i + 1);
      }
    };
    try {
      return await attempt(0);
    } finally {
      clearTimeout(t);
    }
  }

  async _tryRefresh() {
    const { auth } = Store.get();
    if (!auth?.refreshToken) return false;
    try {
      const res = await fetch(`${this.base}/auth/refresh`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...(this.csrfToken ? { [this.csrfHeader]: this.csrfToken } : {}) },
        body: JSON.stringify({ refresh_token: auth.refreshToken }),
      });
      if (!res.ok) return false;
      const json = await res.json();
      Store.set({ auth: { ...auth, token: json.access_token, refreshToken: json.refresh_token || auth.refreshToken } });
      return true;
    } catch { return false; }
  }

  // Конкретные эндпоинты DataFabric (минимально необходимые для админки)

  health() { return this.fetch("/health"); }

  // Jobs (batch/airflow facade)
  listJobs({ q = "", limit = 25, offset = 0, order = "desc" } = {}) {
    const p = new URLSearchParams({ q, limit, offset, order });
    return this.fetch(`/jobs?${p.toString()}`);
  }
  triggerJob(id, params = {}) {
    return this.fetch(`/jobs/${encodeURIComponent(id)}/trigger`, { method: "POST", body: params });
  }

  // Lineage (summary graph per dataset)
  lineage(dataset) {
    return this.fetch(`/lineage/${encodeURIComponent(dataset)}`);
  }

  // Governance (consent)
  listConsents({ subject_id = "", limit = 25, offset = 0 } = {}) {
    const p = new URLSearchParams({ subject_id, limit, offset });
    return this.fetch(`/governance/consents?${p.toString()}`);
  }
  revokeConsent(consent_id) {
    return this.fetch(`/governance/consents/${encodeURIComponent(consent_id)}/revoke`, { method: "POST" });
  }

  // Security (KMS)
  listKeys() { return this.fetch(`/security/kms/keys`); }
  rotateKey(key_id) { return this.fetch(`/security/kms/${encodeURIComponent(key_id)}/rotate`, { method: "POST" }); }

  // Auth
  login(username, password) {
    return this.fetch("/auth/login", { method: "POST", body: { username, password } });
  }
  profile() { return this.fetch("/auth/me"); }
}

class HTTPError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

// anySignal polyfill
function anySignal(signals) {
  const controller = new AbortController();
  const onAbort = s => { if (!controller.signal.aborted) controller.abort(s.reason); };
  signals.forEach(s => s.addEventListener("abort", () => onAbort(s), { once: true }));
  return controller.signal;
}

const sleep = ms => new Promise(r => setTimeout(r, ms));
const backoff = (i, base, jitter) => Math.min(8000, Math.round((2 ** i) * base + Math.random() * jitter));
const safeText = async (res) => { try { return await res.text(); } catch { return ""; } };

const api = new APIClient(cfg.apiBase, {
  timeoutMs: cfg.requestTimeoutMs,
  retry: cfg.retry,
  csrfHeader: cfg.csrfHeader,
  csrfToken: cfg.csrfToken
});

/* =========================================
 *  Router
 * ========================================= */
const Router = (() => {
  const routes = new Map(); // path -> { component, title, guard }
  let notFound = null;

  const register = (path, component, { title, guard } = {}) => {
    routes.set(path, { component, title, guard });
  };
  const setNotFound = (component) => { notFound = component; };

  const parseHash = () => {
    const raw = location.hash.replace(/^#/, "") || "/dashboard";
    const [path, qs] = raw.split("?");
    const p = new URLSearchParams(qs || "");
    return { path, query: p };
  };

  const navigate = (path) => { if (location.hash !== `#${path}`) location.hash = `#${path}`; else render(); };

  const render = async () => {
    const { path, query } = parseHash();
    let entry = routes.get(path);
    if (!entry) entry = routes.get(path.replace(/\/$/, "")) || null;
    let Comp = entry?.component || notFound;
    if (!Comp) return;
    const guard = entry?.guard;
    if (guard && !(await guard({ path, query }))) { return; }
    document.title = `${cfg.appTitle} — ${entry?.title || "Admin"}`;
    const root = $("#app");
    root.replaceChildren(Spinner());
    try {
      const vnode = await Comp({ path, query });
      root.replaceChildren(vnode);
      highlightActiveNav(path);
    } catch (e) {
      root.replaceChildren(ErrorPanel(e));
    }
  };

  window.addEventListener("hashchange", () => render());
  return { register, setNotFound, navigate, render };
})();

/* =========================================
 *  RBAC guard
 * ========================================= */
const requireAuth = async () => {
  const { auth } = Store.get();
  if (!auth?.token) {
    Router.navigate("/login");
    return false;
  }
  // Ленивая загрузка профиля
  if (!auth.profile) {
    try {
      const profile = await api.profile();
      Store.set({ auth: { ...auth, profile } });
    } catch (e) {
      Toast.error("Сессия истекла, войдите снова.");
      Store.set({ auth: { token: null, refreshToken: null, profile: null } });
      Router.navigate("/login");
      return false;
    }
  }
  return true;
};

/* =========================================
 *  UI Components
 * ========================================= */
function AppShell(children) {
  return el("div", { class: "df-app" }, [
    el("style", {}, [`
      :root{
        --bg:#0b0f13; --panel:#131a21; --muted:#a7b0ba; --fg:#e6edf3; --acc:#3da9fc; --danger:#ff6b6b; --ok:#4cc38a; --warn:#f7b955;
        --border:#1f2833; --shadow:0 8px 30px rgba(0,0,0,.35);
      }
      *{box-sizing:border-box}
      body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,"Helvetica Neue",Arial}
      a{color:var(--fg);text-decoration:none}
      .df-shell{display:grid;grid-template-columns:240px 1fr;min-height:100vh}
      .df-side{background:var(--panel);border-right:1px solid var(--border);padding:16px;position:sticky;top:0;height:100vh}
      .df-brand{font-weight:700;margin:0 0 12px 0}
      .df-ver{color:var(--muted);font-size:12px;margin-bottom:16px}
      .df-nav a{display:block;padding:10px 12px;border-radius:8px;color:var(--muted)}
      .df-nav a.active{background:#18222c;color:var(--fg)}
      .df-main{padding:18px 22px}
      .df-header{display:flex;align-items:center;gap:12px;margin-bottom:16px}
      .df-h1{font-size:18px;margin:0}
      .df-chip{font-size:11px;color:var(--muted);padding:2px 8px;border:1px solid var(--border);border-radius:999px}
      .df-actions{margin-left:auto;display:flex;gap:8px}
      .btn{background:#18222c;border:1px solid var(--border);color:var(--fg);padding:8px 10px;border-radius:8px;cursor:pointer}
      .btn:hover{border-color:#2b3744}
      .btn.acc{background:var(--acc);border-color:var(--acc);color:#081018}
      .btn.danger{background:transparent;border-color:var(--danger);color:var(--danger)}
      .btn:disabled{opacity:.6;cursor:not-allowed}
      .card{background:var(--panel);border:1px solid var(--border);border-radius:12px;box-shadow:var(--shadow);padding:14px}
      .grid{display:grid;gap:12px}
      .grid.cols-3{grid-template-columns:repeat(3,minmax(0,1fr))}
      .stat{display:flex;flex-direction:column;gap:2px}
      .muted{color:var(--muted)}
      .table{width:100%;border-collapse:separate;border-spacing:0 6px}
      .table th{font-weight:600;color:var(--muted);text-align:left;font-size:12px;padding:6px 10px}
      .table td{background:#0e141b;border:1px solid var(--border);padding:10px;border-left:0;border-right:0}
      .table tr td:first-child{border-left:1px solid var(--border);border-top-left-radius:8px;border-bottom-left-radius:8px}
      .table tr td:last-child{border-right:1px solid var(--border);border-top-right-radius:8px;border-bottom-right-radius:8px}
      .toolbar{display:flex;gap:8px;align-items:center;margin-bottom:10px}
      .inp{background:#0e141b;border:1px solid var(--border);color:var(--fg);padding:8px 10px;border-radius:8px;outline:none}
      .inp:focus{border-color:#2b3744}
      .kbd{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace;background:#0b1117;border:1px solid var(--border);padding:1px 6px;border-radius:6px}
      .toast-wrap{position:fixed;bottom:16px;right:16px;display:flex;flex-direction:column;gap:8px;z-index:50}
      .toast{background:#101820;border:1px solid var(--border);padding:10px 12px;border-radius:8px;box-shadow:var(--shadow)}
      .toast.ok{border-color:var(--ok)}
      .toast.err{border-color:var(--danger)}
      .modal-backdrop{position:fixed;inset:0;background:rgba(0,0,0,.55);display:flex;align-items:center;justify-content:center;z-index:60}
      .modal{background:var(--panel);border:1px solid var(--border);border-radius:12px;min-width:360px;max-width:90vw;padding:16px}
      .spinner{width:28px;height:28px;border:3px solid #22303d;border-top-color:var(--acc);border-radius:50%;animation:spin 1s linear infinite;margin:28px auto}
      @keyframes spin{to{transform:rotate(360deg)}}
      .badge{font-size:11px;border:1px solid var(--border);padding:2px 6px;border-radius:6px}
      .badge.ok{color:var(--ok);border-color:var(--ok)}
      .badge.err{color:var(--danger);border-color:var(--danger)}
      .offline{position:fixed;top:0;left:0;right:0;background:#3a0f0f;color:#ffdada;text-align:center;padding:6px;font-size:12px;z-index:70}
    `]),
    el("div", { class: "df-shell" }, [
      el("aside", { class: "df-side" }, [
        el("h1", { class: "df-brand" }, [cfg.appTitle]),
        el("div", { class: "df-ver" }, [`v${cfg.version}`]),
        el("nav", { class: "df-nav" }, [
          NavLink("/dashboard", "Дашборд"),
          NavLink("/jobs", "Задания"),
          NavLink("/lineage", "Lineage"),
          NavLink("/consents", "Согласия"),
          NavLink("/kms", "KMS"),
          NavLink("/settings", "Настройки"),
        ]),
        el("div", { style: "margin-top:auto" }, [
          el("hr", { style: "border:0;border-top:1px solid var(--border);margin:12px 0" }),
          ProfilePanel()
        ])
      ]),
      el("main", { class: "df-main" }, [children])
    ]),
    Toast.Container()
  ]);
}

function highlightActiveNav(path) {
  $$(".df-nav a").forEach(a => a.classList.toggle("active", a.getAttribute("href") === `#${path}`));
}

function NavLink(path, label) {
  return el("a", { href: `#${path}` }, [label]);
}

function Header(title, right = null) {
  return el("div", { class: "df-header" }, [
    el("h2", { class: "df-h1" }, [title]),
    el("span", { class: "df-chip", id: "df-health" }, ["проверка..."]),
    el("div", { class: "df-actions" }, [right])
  ]);
}

function Spinner() { return el("div", { class: "spinner", role: "status", "aria-label": "Загрузка" }); }

function ErrorPanel(err) {
  console.error(err);
  return AppShell(el("div", {}, [
    Header("Ошибка"),
    el("div", { class: "card" }, [
      el("div", { class: "muted" }, [String(err?.message || err || "Unknown error")])
    ])
  ]));
}

const Toast = (() => {
  const Container = () => el("div", { class: "toast-wrap", id: "toasts" });
  const push = (msg, type = "ok") => {
    const wrap = $("#toasts"); if (!wrap) return;
    const node = el("div", { class: `toast ${type === "error" ? "err" : "ok"}` }, [sanitize(msg)]);
    wrap.append(node);
    setTimeout(() => node.remove(), 4000);
  };
  return { Container, ok: (m) => push(m, "ok"), error: (m) => push(m, "error") };
})();

function ConfirmDialog({ title = "Подтверждение", body = "", onConfirm, onCancel }) {
  const close = () => backdrop.remove();
  const backdrop = el("div", { class: "modal-backdrop", role: "dialog", "aria-modal": "true" }, [
    el("div", { class: "modal" }, [
      el("h3", {}, [title]),
      el("div", { class: "muted", style: "margin:8px 0 12px" }, [sanitize(body)]),
      el("div", { style: "display:flex;gap:8px;justify-content:flex-end" }, [
        el("button", { class: "btn", onClick: () => { onCancel?.(); close(); } }, ["Отмена"]),
        el("button", { class: "btn acc", onClick: () => { onConfirm?.(); close(); } }, ["ОК"]),
      ])
    ])
  ]);
  backdrop.addEventListener("click", (e) => { if (e.target === backdrop) onCancel?.(); });
  document.body.appendChild(backdrop);
  return backdrop;
}

function Table({ columns, rows, key = "id", onSort, sortBy, sortDir = "asc" }) {
  const thead = el("thead", {}, [el("tr", {}, columns.map(c => {
    const th = el("th", {}, [c.label]);
    if (c.sortable) {
      th.style.cursor = "pointer";
      th.addEventListener("click", () => onSort?.(c.field, sortBy === c.field && sortDir === "asc" ? "desc" : "asc"));
    }
    return th;
  }))]);

  const tbody = el("tbody", {}, rows.map(r => {
    return el("tr", { dataset: { key: r[key] } }, columns.map(c => el("td", {}, [c.render ? c.render(r[c.field], r) : sanitize(r[c.field])])));
  }));
  return el("table", { class: "table", role: "table" }, [thead, tbody]);
}

/* =========================================
 *  Views
 * ========================================= */

async function DashboardView() {
  // Загружаем метрики health
  let health;
  try { health = await api.health(); } catch (e) { health = { ok: false, error: e.message }; }
  const healthy = !!health?.ok;
  const badge = el("span", { class: `badge ${healthy ? "ok" : "err"}` }, [healthy ? "OK" : "ERROR"]);

  const grid = el("div", { class: "grid cols-3" }, [
    Stat("Состояние", healthy ? "Онлайн" : "Проблемы", healthy ? "Сервисы отвечают" : sanitize(health?.error || "—")),
    Stat("Версия", sanitize(health?.version || "—"), "DataFabric Core"),
    Stat("Очередей", String(health?.queues ?? "—"), "Обработка задач"),
  ]);

  return AppShell(el("div", {}, [
    Header("Дашборд"),
    el("div", { class: "card", style: "margin-bottom:12px" }, [
      el("div", { style: "display:flex;align-items:center;gap:10px" }, [
        el("span", {}, ["Статус: "]), badge
      ])
    ]),
    grid
  ]));
}
function Stat(title, value, hint) {
  return el("div", { class: "card stat" }, [
    el("div", { class: "muted" }, [title]),
    el("div", { style: "font-weight:700;font-size:18px" }, [value]),
    hint ? el("div", { class: "muted", style: "font-size:12px" }, [hint]) : null
  ]);
}

async function JobsView({ query }) {
  const q = query.get("q") || "";
  const state = { sortBy: "started_at", sortDir: "desc", limit: 25, offset: 0, q };
  const container = el("div");
  const renderList = async () => {
    container.replaceChildren(Header("Задания", el("div", {}, [
      el("input", { class: "inp", placeholder: "Поиск по ID/имени", value: state.q, oninput: (e) => { state.q = e.target.value; debounceLoad(); } }),
      el("button", { class: "btn", style: "margin-left:8px", onClick: () => Router.navigate(`/jobs?q=${encodeURIComponent(state.q)}`) }, ["Искать"])
    ])));
    const wrap = el("div", { class: "card" }, [Spinner()]);
    container.appendChild(wrap);
    try {
      const data = await api.listJobs({ q: state.q, limit: state.limit, offset: state.offset, order: state.sortDir });
      const rows = (data.items || []).map(x => ({
        id: x.id, name: x.name, status: x.status, started_at: x.started_at, duration_ms: x.duration_ms
      }));
      const table = Table({
        columns: [
          { field: "id", label: "ID", sortable: false, render: (v) => el("span", { class: "kbd" }, [shortId(v)]) },
          { field: "name", label: "Имя", sortable: true },
          { field: "status", label: "Статус", sortable: true, render: (v) => el("span", { class: `badge ${v === "success" ? "ok" : v === "failed" ? "err" : ""}` }, [v]) },
          { field: "started_at", label: "Старт", sortable: true, render: (v) => dateFmt(v) },
          { field: "duration_ms", label: "Длительность", sortable: true, render: (v) => `${(v/1000).toFixed(1)}s` },
          { field: "actions", label: "", render: (_, r) => el("button", { class: "btn", onClick: () => trigger(r.id) }, ["Перезапуск"]) },
        ],
        rows,
        onSort: (f, d) => { state.sortBy = f; state.sortDir = d; renderList(); },
        sortBy: state.sortBy,
        sortDir: state.sortDir
      });
      wrap.replaceChildren(table, Paginator({
        total: data.total || rows.length, limit: state.limit, offset: state.offset,
        onPage: (o) => { state.offset = o; renderList(); }
      }));
    } catch (e) {
      wrap.replaceChildren(el("div", { class: "muted" }, [sanitize(e.message)]));
    }
  };
  const debounceLoad = debounce(renderList, 300);

  const trigger = (id) => {
    ConfirmDialog({
      title: "Перезапустить задание",
      body: `Перезапустить ${sanitize(id)}?`,
      onConfirm: async () => {
        try { await api.triggerJob(id, {}); Toast.ok("Задание отправлено"); renderList(); }
        catch (e) { Toast.error(e.message || "Ошибка"); }
      }
    });
  };

  await renderList();
  return AppShell(container);
}

async function LineageView() {
  const container = el("div");
  container.appendChild(Header("Lineage"));
  const card = el("div", { class: "card" }, [
    el("div", { class: "toolbar" }, [
      el("input", { class: "inp", placeholder: "dataset (schema.table)", id: "ds" }),
      el("button", { class: "btn", onClick: async () => {
        const ds = $("#ds").value.trim();
        if (!ds) return;
        card.replaceChildren(Spinner());
        try {
          const g = await api.lineage(ds);
          card.replaceChildren(LineageGraph(g));
        } catch (e) {
          card.replaceChildren(el("div", { class: "muted" }, [sanitize(e.message)]));
        }
      } }, ["Загрузить"])
    ])
  ]);
  container.appendChild(card);
  return AppShell(container);
}
function LineageGraph(g) {
  // Очень минимальная визуализация: список узлов и рёбер
  const nodes = el("div", {}, [
    el("div", { class: "muted", style: "margin-bottom:6px" }, ["Узлы"]),
    el("ul", {}, (g?.nodes || []).map(n => el("li", {}, [sanitize(n)]))),
    el("div", { class: "muted", style: "margin:12px 0 6px" }, ["Связи"]),
    el("ul", {}, (g?.edges || []).map(e => el("li", {}, [
      sanitize(`${e.source.table}.${e.source.column} -> ${e.target.table}.${e.target.column} [${e.kind}]`)
    ]))),
  ]);
  return el("div", { class: "card" }, [nodes]);
}

async function ConsentsView() {
  const container = el("div");
  container.appendChild(Header("Согласия"));
  const card = el("div", { class: "card" }, [Spinner()]);
  container.appendChild(card);
  try {
    const data = await api.listConsents({ limit: 25, offset: 0 });
    const rows = (data.items || []).map(x => ({
      id: x.consent_id, subject: x.key?.subject_id, controller: x.key?.controller_id, purpose: x.key?.purpose_id,
      status: x.status, granted_at: x.granted_at, expires_at: x.expires_at
    }));
    const table = Table({
      columns: [
        { field: "id", label: "ID", render: (v) => el("span", { class: "kbd" }, [shortId(v)]) },
        { field: "subject", label: "Subject" },
        { field: "controller", label: "Controller" },
        { field: "purpose", label: "Purpose" },
        { field: "status", label: "Статус", render: v => el("span", { class: `badge ${v === "granted" ? "ok" : "err"}` }, [v]) },
        { field: "granted_at", label: "Выдано", render: dateFmt },
        { field: "expires_at", label: "Истекает", render: dateFmt },
        { field: "actions", label: "", render: (_, r) => el("button", { class: "btn danger", onClick: () => revoke(r.id) }, ["Отозвать"]) },
      ],
      rows
    });
    card.replaceChildren(table);
  } catch (e) {
    card.replaceChildren(el("div", { class: "muted" }, [sanitize(e.message)]));
  }
  const revoke = (id) => {
    ConfirmDialog({
      title: "Отозвать согласие",
      body: `Отозвать согласие ${sanitize(id)}?`,
      onConfirm: async () => {
        try { await api.revokeConsent(id); Toast.ok("Согласие отозвано"); Router.render(); }
        catch (e) { Toast.error(e.message || "Ошибка"); }
      }
    });
  };
  return AppShell(container);
}

async function KMSView() {
  const container = el("div");
  container.appendChild(Header("KMS"));
  const card = el("div", { class: "card" }, [Spinner()]);
  container.appendChild(card);
  try {
    const data = await api.listKeys();
    const rows = (data.items || []).map(x => ({ key_id: x.key_id, created_at: x.created_at, type: x.type }));
    const table = Table({
      columns: [
        { field: "key_id", label: "Key ID", render: v => el("span", { class: "kbd" }, [shortId(v)]) },
        { field: "type", label: "Тип" },
        { field: "created_at", label: "Создан", render: dateFmt },
        { field: "actions", label: "", render: (_, r) => el("button", { class: "btn", onClick: () => rotate(r.key_id) }, ["Ротировать"]) },
      ], rows
    });
    card.replaceChildren(table);
  } catch (e) {
    card.replaceChildren(el("div", { class: "muted" }, [sanitize(e.message)]));
  }
  const rotate = (keyId) => {
    ConfirmDialog({
      title: "Ротация ключа",
      body: `Ротация ключа ${sanitize(keyId)}?`,
      onConfirm: async () => {
        try { await api.rotateKey(keyId); Toast.ok("Ключ ротирован"); Router.render(); }
        catch (e) { Toast.error(e.message || "Ошибка"); }
      }
    });
  };
  return AppShell(container);
}

async function SettingsView() {
  const { auth } = Store.get();
  const logout = () => {
    Store.set({ auth: { token: null, refreshToken: null, profile: null } });
    Router.navigate("/login");
  };
  return AppShell(el("div", {}, [
    Header("Настройки"),
    el("div", { class: "card", style: "display:flex;gap:10px;align-items:center" }, [
      el("div", {}, [
        el("div", {}, ["Пользователь: ", el("span", { class: "kbd" }, [sanitize(auth?.profile?.username || "—")])]),
        el("div", { class: "muted" }, [sanitize(auth?.profile?.role || "—")]),
      ]),
      el("div", { style: "margin-left:auto" }, [
        el("button", { class: "btn danger", onClick: logout }, ["Выйти"])
      ])
    ])
  ]));
}

function ProfilePanel() {
  const { auth } = Store.get();
  if (!auth?.profile) return el("div", { class: "muted" }, ["Не авторизован"]);
  return el("div", {}, [
    el("div", {}, [sanitize(auth.profile.username || "")]),
    el("div", { class: "muted", style: "font-size:12px" }, [sanitize(auth.profile.role || "")])
  ]);
}

async function LoginView() {
  const root = el("div");
  const form = el("form", { class: "card", style: "max-width:420px" }, [
    el("h3", {}, ["Вход"]),
    el("label", { class: "muted" }, ["Логин"]),
    el("input", { class: "inp", type: "text", required: true, id: "u" }),
    el("label", { class: "muted", style: "margin-top:8px" }, ["Пароль"]),
    el("input", { class: "inp", type: "password", required: true, id: "p" }),
    el("div", { style: "display:flex;gap:8px;justify-content:flex-end;margin-top:12px" }, [
      el("button", { type: "submit", class: "btn acc" }, ["Войти"])
    ])
  ]);
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const u = $("#u", form).value.trim();
    const p = $("#p", form).value;
    try {
      const res = await api.login(u, p);
      Store.set({ auth: { token: res.access_token, refreshToken: res.refresh_token || null, profile: null } });
      Router.navigate("/dashboard");
      Toast.ok("Успешный вход");
    } catch (err) {
      Toast.error(err.message || "Ошибка входа");
    }
  });
  root.appendChild(AppShell(form));
  return root;
}

/* =========================================
 *  Widgets: paginator, debounce, helpers
 * ========================================= */
function Paginator({ total, limit, offset, onPage }) {
  const pages = Math.max(1, Math.ceil(total / limit));
  const current = Math.floor(offset / limit) + 1;
  const wrap = el("div", { class: "toolbar" }, [
    el("span", { class: "muted" }, [`Стр. ${current}/${pages}`]),
    el("button", { class: "btn", onClick: () => onPage(Math.max(0, offset - limit)), disabled: current <= 1 }, ["Назад"]),
    el("button", { class: "btn", onClick: () => onPage(Math.min((pages - 1) * limit, offset + limit)), disabled: current >= pages }, ["Вперёд"]),
  ]);
  return wrap;
}
const debounce = (fn, ms = 300) => {
  let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
};
const shortId = (v) => !v ? "" : String(v).slice(0, 8);

/* =========================================
 *  Health badge updater, online/offline, errors
 * ========================================= */
async function updateHealthBadge() {
  try {
    const h = await api.health();
    const badge = $("#df-health"); if (!badge) return;
    badge.textContent = h?.ok ? "healthy" : "degraded";
    badge.className = `df-chip`;
  } catch {
    const badge = $("#df-health"); if (!badge) return;
    badge.textContent = "offline";
  }
}
setInterval(updateHealthBadge, 10000);

window.addEventListener("online", () => { Store.set({ online: true }); removeOfflineBanner(); });
window.addEventListener("offline", () => { Store.set({ online: false }); showOfflineBanner(); });
function showOfflineBanner() { if (!$(".offline")) document.body.appendChild(el("div", { class: "offline" }, ["Нет сети. Работа в офлайн."])); }
function removeOfflineBanner() { $(".offline")?.remove(); }

window.addEventListener("error", (e) => {
  console.error("GlobalError:", e.error || e.message);
  Toast.error(`Ошибка: ${sanitize(e.message)}`);
});
window.addEventListener("unhandledrejection", (e) => {
  console.error("UnhandledRejection:", e.reason);
  Toast.error(`Ошибка: ${sanitize(e.reason?.message || e.reason)}`);
});

/* =========================================
 *  App bootstrap
 * ========================================= */
Router.register("/login", LoginView, { title: "Вход" });
Router.register("/dashboard", () => requireAuth().then(ok => ok && DashboardView()), { title: "Дашборд", guard: requireAuth });
Router.register("/jobs", (ctx) => requireAuth().then(ok => ok && JobsView(ctx)), { title: "Задания", guard: requireAuth });
Router.register("/lineage", () => requireAuth().then(ok => ok && LineageView()), { title: "Lineage", guard: requireAuth });
Router.register("/consents", () => requireAuth().then(ok => ok && ConsentsView()), { title: "Согласия", guard: requireAuth });
Router.register("/kms", () => requireAuth().then(ok => ok && KMSView()), { title: "KMS", guard: requireAuth });
Router.register("/settings", () => requireAuth().then(ok => ok && SettingsView()), { title: "Настройки", guard: requireAuth });
Router.setNotFound(() => AppShell(el("div", {}, [Header("Не найдено"), el("div", { class: "card" }, ["Страница не найдена"]) ])));

document.addEventListener("DOMContentLoaded", () => {
  // Первичная отрисовка
  $("#app")?.replaceChildren(AppShell(Spinner()));
  Router.render();
  updateHealthBadge();
});
