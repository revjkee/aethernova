// policy-core/clients/web-admin-minimal/main.js
/* eslint-disable no-console */
(() => {
  'use strict';

  // =============== Utilities ===============
  const now = () => Date.now();
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const clamp = (x, lo, hi) => Math.min(hi, Math.max(lo, x));
  const jsonSafe = (v, fallback = null) => {
    try { return JSON.parse(v); } catch { return fallback; }
  };
  const deepFreeze = (obj) => {
    if (obj && typeof obj === 'object' && !Object.isFrozen(obj)) {
      Object.freeze(obj);
      for (const k of Object.keys(obj)) deepFreeze(obj[k]);
    }
    return obj;
  };
  const uid = (prefix = 'id') => {
    if (window.crypto && crypto.getRandomValues) {
      const a = new Uint32Array(2); crypto.getRandomValues(a);
      return `${prefix}-${a[0].toString(16)}${a[1].toString(16)}`;
    }
    return `${prefix}-${Math.random().toString(16).slice(2)}`;
  };

  // Strictly build DOM without innerHTML to avoid XSS
  const el = (tag, attrs = {}, children = []) => {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === 'text') node.textContent = v;
      else if (k === 'class') node.className = v;
      else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2), v);
      else node.setAttribute(k, String(v));
    }
    if (!Array.isArray(children)) children = [children];
    for (const ch of children) {
      if (ch == null) continue;
      if (typeof ch === 'string' || typeof ch === 'number') node.appendChild(document.createTextNode(String(ch)));
      else node.appendChild(ch);
    }
    return node;
  };
  const clear = (node) => { while (node.firstChild) node.removeChild(node.firstChild); };

  // =============== Configuration ===============
  const readMeta = (name) => {
    const m = document.querySelector(`meta[name="${name}"]`);
    return m ? m.getAttribute('content') : null;
  };

  const DEFAULT_CONFIG = deepFreeze({
    appName: 'policy-admin',
    version: '0.1.0',
    apiBase: '/api',
    requestTimeoutMs: 10000,
    retry: { retries: 2, baseDelayMs: 300, maxDelayMs: 2000 },
    features: {
      telemetry: true,
      remoteLogs: false,
      allowTokenStorage: false
    },
    storageKeys: {
      tokens: 'policy_admin_tokens_v1'
    }
  });

  const merge = (base, patch) => {
    if (!patch || typeof patch !== 'object') return base;
    const out = Array.isArray(base) ? base.slice() : { ...base };
    for (const k of Object.keys(patch)) {
      const bv = base?.[k], pv = patch[k];
      out[k] = (bv && typeof bv === 'object' && !Array.isArray(bv) && typeof pv === 'object' && !Array.isArray(pv))
        ? merge(bv, pv)
        : pv;
    }
    return out;
  };

  const BOOT_CONFIG = (() => {
    const fromWin = typeof window.__APP_CONFIG__ !== 'undefined' ? window.__APP_CONFIG__ : null;
    const fromMeta = jsonSafe(readMeta('app-config'), null);
    const cfg = merge(DEFAULT_CONFIG, merge(fromWin, fromMeta));
    const csrf = readMeta('csrf-token');
    if (csrf) cfg.csrfToken = csrf;
    return deepFreeze(cfg);
  })();

  // =============== Logger ===============
  const Logger = (() => {
    const levelRank = { debug: 10, info: 20, warn: 30, error: 40 };
    const globalLevel = (readMeta('log-level') || 'info').toLowerCase();

    function shouldLog(lvl) { return levelRank[lvl] >= levelRank[globalLevel]; }
    async function remoteSend(payload) {
      if (!BOOT_CONFIG.features.remoteLogs) return;
      try {
        await fetch(`${BOOT_CONFIG.apiBase}/admin/logs`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
          credentials: 'include'
        });
      } catch { /* swallow */ }
    }

    function mk(level) {
      return (name, msg, extra) => {
        if (!shouldLog(level)) return;
        const line = `[${level.toUpperCase()}] [${name}] ${msg}`;
        (console[level] || console.log)(line, extra || '');
        remoteSend({ t: new Date().toISOString(), level, name, msg, extra });
      };
    }

    return deepFreeze({
      debug: mk('debug'),
      info: mk('info'),
      warn: mk('warn'),
      error: mk('error')
    });
  })();

  // =============== Tokens ===============
  const TokenManager = (() => {
    let access = null, refresh = null, exp = 0;
    const key = BOOT_CONFIG.storageKeys.tokens;
    const allowStore = !!BOOT_CONFIG.features.allowTokenStorage;

    function load() {
      try {
        if (!allowStore) return;
        const raw = sessionStorage.getItem(key);
        if (!raw) return;
        const obj = jsonSafe(raw, null);
        if (!obj) return;
        access = obj.access || null;
        refresh = obj.refresh || null;
        exp = obj.exp || 0;
      } catch { /* ignore */ }
    }
    function save() {
      try {
        if (!allowStore) return;
        const obj = { access, refresh, exp };
        sessionStorage.setItem(key, JSON.stringify(obj));
      } catch { /* ignore */ }
    }
    function setTokens(t) {
      access = t?.access || null;
      refresh = t?.refresh || null;
      exp = t?.exp || 0;
      save();
    }
    function getAccess() { return access; }
    function expiredSoon(deltaMs = 15000) { return access && exp && now() + deltaMs >= exp; }
    async function refreshFlow() {
      if (!refresh) return false;
      try {
        const r = await fetch(`${BOOT_CONFIG.apiBase}/auth/refresh`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', ...(BOOT_CONFIG.csrfToken ? { 'X-CSRF': BOOT_CONFIG.csrfToken } : {}) },
          body: JSON.stringify({ refresh }),
          credentials: 'include'
        });
        if (!r.ok) return false;
        const data = await r.json();
        setTokens({ access: data.access, refresh: data.refresh || refresh, exp: (data.exp || 0) * 1000 });
        return true;
      } catch {
        return false;
      }
    }
    load();
    return { setTokens, getAccess, expiredSoon, refreshFlow };
  })();

  // =============== HTTP client ===============
  const Http = (() => {
    async function request(path, opts = {}) {
      const method = (opts.method || 'GET').toUpperCase();
      const body = opts.body != null ? (typeof opts.body === 'string' ? opts.body : JSON.stringify(opts.body)) : null;
      const headers = { Accept: 'application/json', ...(body ? { 'Content-Type': 'application/json' } : {}), ...(opts.headers || {}) };
      const base = BOOT_CONFIG.apiBase.replace(/\/+$/, '');
      const url = `${base}${path.startsWith('/') ? '' : '/'}${path}`;

      const withAuth = !!TokenManager.getAccess();
      if (withAuth) headers.Authorization = `Bearer ${TokenManager.getAccess()}`;
      if (BOOT_CONFIG.csrfToken) headers['X-CSRF'] = BOOT_CONFIG.csrfToken;

      const timeoutMs = BOOT_CONFIG.requestTimeoutMs;
      const retries = Math.max(0, (opts.retries ?? BOOT_CONFIG.retry.retries));
      const baseDelay = BOOT_CONFIG.retry.baseDelayMs;
      const maxDelay = BOOT_CONFIG.retry.maxDelayMs;

      let attempt = 0;
      while (true) {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        try {
          // Refresh access token if near expiry
          if (TokenManager.expiredSoon() && attempt === 0) {
            await TokenManager.refreshFlow();
            if (TokenManager.getAccess()) headers.Authorization = `Bearer ${TokenManager.getAccess()}`;
          }

          const res = await fetch(url, { method, headers, body, credentials: 'include', signal: controller.signal, mode: 'same-origin' });
          clearTimeout(timer);

          if (res.status === 401 && withAuth && attempt <= retries) {
            // Try one refresh then retry
            const ok = await TokenManager.refreshFlow();
            if (ok) {
              headers.Authorization = `Bearer ${TokenManager.getAccess()}`;
              attempt += 1;
              continue;
            }
          }

          if ((res.status >= 500 || res.status === 429) && attempt < retries) {
            const delay = clamp(baseDelay * Math.pow(2, attempt) + Math.random() * 100, baseDelay, maxDelay);
            await sleep(delay);
            attempt += 1;
            continue;
          }

          const text = await res.text();
          const data = text ? jsonSafe(text, { raw: text }) : null;

          if (!res.ok) {
            const err = new Error(`HTTP ${res.status}`);
            err.status = res.status;
            err.data = data;
            throw err;
          }
          return data;
        } catch (e) {
          clearTimeout(timer);
          if (e.name === 'AbortError') {
            if (attempt < retries) { attempt += 1; continue; }
            const err = new Error('Request timeout');
            err.status = 0;
            throw err;
          }
          if (attempt < retries) { attempt += 1; continue; }
          throw e;
        }
      }
    }

    return { request };
  })();

  // =============== Router ===============
  const Router = (() => {
    const routes = {};
    let notFound = null;
    function register(path, handler) { routes[path] = handler; }
    function setNotFound(handler) { notFound = handler; }
    function parseHash() {
      const h = (location.hash || '').replace(/^#/, '');
      return h || '/';
    }
    async function navigate() {
      const path = parseHash();
      const handler = routes[path] || notFound;
      if (typeof handler === 'function') await handler();
    }
    window.addEventListener('hashchange', navigate);
    return { register, setNotFound, navigate };
  })();

  // =============== Telemetry ===============
  const Telemetry = (() => {
    const enabled = !!BOOT_CONFIG.features.telemetry;
    function send(endpoint, payload) {
      if (!enabled) return;
      try {
        navigator.sendBeacon?.(`${BOOT_CONFIG.apiBase}${endpoint}`, new Blob([JSON.stringify(payload)], { type: 'application/json' }));
      } catch { /* ignore */ }
    }
    window.addEventListener('error', (e) => {
      send('/admin/telemetry/errors', {
        t: new Date().toISOString(),
        type: 'error',
        msg: String(e.message || ''),
        src: String(e.filename || ''),
        line: e.lineno || 0,
        col: e.colno || 0
      });
    });
    window.addEventListener('unhandledrejection', (e) => {
      send('/admin/telemetry/errors', {
        t: new Date().toISOString(),
        type: 'unhandledrejection',
        msg: String(e.reason && e.reason.message || e.reason || '')
      });
    });
    window.addEventListener('load', () => {
      try {
        const [nt] = performance.getEntriesByType('navigation');
        if (nt) {
          send('/admin/telemetry/perf', {
            t: new Date().toISOString(),
            type: 'navigation',
            dom: nt.domComplete,
            fcp: performance.getEntriesByName('first-contentful-paint')[0]?.startTime || null
          });
        }
      } catch { /* ignore */ }
    });
    return { send };
  })();

  // =============== Store (simple pubsub) ===============
  const Store = (() => {
    const subs = new Map();
    function on(topic, fn) {
      if (!subs.has(topic)) subs.set(topic, new Set());
      subs.get(topic).add(fn);
      return () => subs.get(topic)?.delete(fn);
    }
    function emit(topic, data) {
      const set = subs.get(topic); if (!set) return;
      for (const fn of set) { try { fn(data); } catch {} }
    }
    return { on, emit };
  })();

  // =============== Views ===============
  const root = (() => {
    let node = document.getElementById('app');
    if (!node) {
      node = el('div', { id: 'app' }, []);
      document.body.appendChild(node);
    }
    return node;
  })();

  function shell(children) {
    const header = el('header', { class: 'pa-header' }, [
      el('div', { class: 'pa-title', text: `${BOOT_CONFIG.appName} v${BOOT_CONFIG.version}` }),
      el('nav', { class: 'pa-nav' }, [
        linkBtn('Dashboard', '#/'),
        linkBtn('Bundles', '#/bundles'),
        linkBtn('Risk', '#/risk'),
        linkBtn('Settings', '#/settings')
      ])
    ]);
    const main = el('main', { class: 'pa-main' }, children);
    const wrap = el('div', { class: 'pa-wrap' }, [header, main]);
    return wrap;
  }

  function linkBtn(text, href) {
    const a = el('a', { href, class: 'pa-link' }, text);
    a.addEventListener('click', (e) => {
      // rely on hashchange
    });
    return a;
  }

  function render(node) {
    clear(root); root.appendChild(node);
  }

  // Dashboard
  async function viewDashboard() {
    const container = el('section', { class: 'pa-section' }, [
      el('h2', { text: 'Dashboard' }),
      el('p', { text: 'Состояние административного интерфейса и API.' }),
      el('div', { class: 'pa-card', id: 'health-block' }, [el('p', { text: 'Проверка здоровья API...' })])
    ]);
    render(shell(container));
    try {
      const health = await Http.request('/admin/health');
      const blk = container.querySelector('#health-block');
      clear(blk);
      blk.appendChild(el('pre', {}, JSON.stringify(health, null, 2)));
    } catch (e) {
      Logger.error('viewDashboard', `Health error: ${e.status || ''}`);
      const blk = container.querySelector('#health-block');
      clear(blk);
      blk.appendChild(el('p', { text: `Ошибка получения состояния: ${e.message}` }));
    }
  }

  // Bundles
  async function viewBundles() {
    const container = el('section', { class: 'pa-section' }, [
      el('h2', { text: 'Bundles' }),
      el('p', { text: 'Список загруженных бандлов политик.' }),
      el('div', { class: 'pa-card', id: 'bundles-list' }, [el('p', { text: 'Загрузка...' })])
    ]);
    render(shell(container));
    try {
      const data = await Http.request('/admin/bundles');
      const list = container.querySelector('#bundles-list');
      clear(list);
      if (!Array.isArray(data) || data.length === 0) {
        list.appendChild(el('p', { text: 'Нет данных.' }));
        return;
      }
      for (const b of data) {
        const row = el('div', { class: 'pa-row' }, [
          el('div', { class: 'pa-col' }, [
            el('div', { class: 'pa-kv' }, [el('span', { class: 'k', text: 'name:' }), el('span', { class: 'v', text: String(b.bundle?.name || '') })]),
            el('div', { class: 'pa-kv' }, [el('span', { class: 'k', text: 'version:' }), el('span', { class: 'v', text: String(b.bundle?.version || '') })])
          ]),
          el('div', { class: 'pa-col' }, [
            el('div', { class: 'pa-kv' }, [el('span', { class: 'k', text: 'signature:' }), el('span', { class: 'v', text: String(b.signature_ok ? 'OK' : 'FAIL') })]),
            el('div', { class: 'pa-kv' }, [el('span', { class: 'k', text: 'integrity:' }), el('span', { class: 'v', text: String(b.integrity_ok ? 'OK' : 'FAIL') })])
          ])
        ]);
        list.appendChild(el('div', { class: 'pa-card' }, row));
      }
    } catch (e) {
      const list = container.querySelector('#bundles-list');
      clear(list);
      list.appendChild(el('p', { text: `Ошибка: ${e.message}` }));
    }
  }

  // Risk
  async function viewRisk() {
    const taId = uid('features');
    const outId = uid('result');
    const submitId = uid('submit');

    const container = el('section', { class: 'pa-section' }, [
      el('h2', { text: 'Risk' }),
      el('p', { text: 'Тестирование скоринга риска. Введите JSON с признаком features.' }),
      el('div', { class: 'pa-card' }, [
        el('label', { for: taId, class: 'pa-label', text: 'Входной JSON' }),
        el('textarea', { id: taId, class: 'pa-textarea', rows: '10' }, '{"features":{"amount":7500,"country":"SE"}}'),
        el('button', { id: submitId, class: 'pa-btn' }, 'Оценить риск'),
      ]),
      el('div', { class: 'pa-card', id: outId }, [el('p', { text: 'Результат появится здесь.' })])
    ]);

    render(shell(container));

    const onSubmit = async () => {
      const src = document.getElementById(taId).value;
      const out = document.getElementById(outId);
      clear(out);
      let payload = null;
      try {
        payload = jsonSafe(src, null);
        if (!payload) throw new Error('Некорректный JSON');
      } catch (e) {
        out.appendChild(el('p', { text: `Ошибка парсинга: ${e.message}` }));
        return;
      }
      try {
        const result = await Http.request('/admin/risk/score', { method: 'POST', body: payload });
        out.appendChild(el('pre', {}, JSON.stringify(result, null, 2)));
      } catch (e) {
        out.appendChild(el('p', { text: `Ошибка запроса: ${e.message}` }));
      }
    };

    document.getElementById(submitId).addEventListener('click', onSubmit);
  }

  // Settings
  async function viewSettings() {
    const container = el('section', { class: 'pa-section' }, [
      el('h2', { text: 'Settings' }),
      el('p', { text: 'Безопасный срез конфигурации клиента.' }),
      el('div', { class: 'pa-card' }, [
        el('pre', {}, JSON.stringify({
          appName: BOOT_CONFIG.appName,
          version: BOOT_CONFIG.version,
          apiBase: BOOT_CONFIG.apiBase,
          requestTimeoutMs: BOOT_CONFIG.requestTimeoutMs,
          retry: BOOT_CONFIG.retry,
          features: BOOT_CONFIG.features
        }, null, 2))
      ])
    ]);
    render(shell(container));
  }

  // 404
  async function viewNotFound() {
    render(shell(el('section', { class: 'pa-section' }, [
      el('h2', { text: 'Not Found' }),
      el('p', { text: 'Маршрут не найден.' })
    ])));
  }

  // =============== Styles (minimal inline) ===============
  // Note: rely on CSP 'style-src self'. No inline style attributes besides classes above.
  (function injectStyles() {
    const css = `
      .pa-wrap { font-family: system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, Arial, sans-serif; color: #0f172a; }
      .pa-header { display:flex; align-items:center; justify-content:space-between; padding:12px 16px; border-bottom:1px solid #e2e8f0; background:#f8fafc; position:sticky; top:0; z-index:5; }
      .pa-title { font-weight:600; }
      .pa-nav .pa-link { margin-right:12px; text-decoration:none; color:#0ea5e9; }
      .pa-nav .pa-link:focus { outline: 2px solid #0ea5e9; outline-offset:2px; }
      .pa-main { max-width: 980px; margin: 16px auto; padding: 0 16px; }
      .pa-section h2 { margin: 0 0 8px 0; font-size: 20px; }
      .pa-card { border:1px solid #e2e8f0; border-radius:12px; padding:12px; margin:12px 0; background:#ffffff; }
      .pa-row { display:flex; gap:16px; }
      .pa-col { flex:1; min-width: 240px; }
      .pa-kv { display:flex; gap:8px; }
      .pa-kv .k { color:#64748b; }
      .pa-kv .v { font-weight:500; }
      .pa-label { display:block; margin-bottom:6px; color:#334155; }
      .pa-textarea { width:100%; box-sizing:border-box; }
      .pa-btn { padding:8px 12px; border-radius:8px; border:1px solid #0ea5e9; background:#0ea5e9; color:#fff; cursor:pointer; }
      .pa-btn:focus { outline:2px solid #0284c7; outline-offset:2px; }
      pre { white-space: pre-wrap; word-break: break-word; margin: 0; }
    `;
    const style = document.createElement('style');
    style.appendChild(document.createTextNode(css));
    document.head.appendChild(style);
  })();

  // =============== Boot ===============
  function mountRoutes() {
    Router.register('/', viewDashboard);
    Router.register('/bundles', viewBundles);
    Router.register('/risk', viewRisk);
    Router.register('/settings', viewSettings);
    Router.setNotFound(viewNotFound);
  }

  async function boot() {
    Logger.info('boot', 'starting web-admin');
    mountRoutes();
    await Router.navigate();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
