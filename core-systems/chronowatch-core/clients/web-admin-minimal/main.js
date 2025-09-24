/* Chronowatch Core — Web Admin Minimal (industrial, dependency-free)
 * Targets: modern evergreen browsers
 * Security: no innerHTML for untrusted data; XSS-safe text rendering
 * API: /v1/healthz, /v1/readyz, /v1/heartbeats, /v1/heartbeats/{service}/latest
 */

(() => {
  "use strict";

  // ========= Config & Storage =========

  const LS = {
    token: "cw.admin.token",
    tenant: "cw.admin.tenant",
    apiBase: "cw.admin.apiBase",
    latestPollMs: "cw.admin.latest.pollMs",
  };

  const DEFAULTS = {
    apiBase: (document.querySelector('meta[name="cw-api-base"]')?.content || "").trim() || `${location.origin}`,
    requestTimeoutMs: 12000,
    retryAttempts: 3,
    retryBaseDelay: 120, // ms
    retryMaxDelay: 1500, // ms
    latestPollMs: 5000,
  };

  const Config = {
    get apiBase() { return localStorage.getItem(LS.apiBase) || DEFAULTS.apiBase; },
    set apiBase(v) { localStorage.setItem(LS.apiBase, (v || "").trim()); },
    get token() { return localStorage.getItem(LS.token) || ""; },
    set token(v) { v ? localStorage.setItem(LS.token, v) : localStorage.removeItem(LS.token); },
    get tenant() { return localStorage.getItem(LS.tenant) || ""; },
    set tenant(v) { v ? localStorage.setItem(LS.tenant, v) : localStorage.removeItem(LS.tenant); },
    get latestPollMs() {
      const n = Number(localStorage.getItem(LS.latestPollMs));
      return Number.isFinite(n) && n > 500 ? n : DEFAULTS.latestPollMs;
    },
    set latestPollMs(v) { localStorage.setItem(LS.latestPollMs, String(v)); },
  };

  // ========= Utilities (DOM, time, id) =========

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  const h = (tag, attrs = {}, ...children) => {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null) continue;
      if (k === "class") el.className = String(v);
      else if (k === "dataset") Object.assign(el.dataset, v);
      else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
      else if (k === "style" && typeof v === "object") Object.assign(el.style, v);
      else el.setAttribute(k, String(v));
    }
    for (const ch of children.flat()) {
      if (ch == null) continue;
      if (typeof ch === "string" || typeof ch === "number") el.appendChild(document.createTextNode(String(ch)));
      else el.appendChild(ch);
    }
    return el;
  };

  const fmtIso = (d) => {
    try { return new Date(d).toISOString(); } catch { return ""; }
  };
  const fmtRel = (d) => {
    const t = new Date(d).getTime();
    if (!Number.isFinite(t)) return "";
    const diff = Date.now() - t;
    const sec = Math.round(Math.abs(diff) / 1000);
    const dir = diff >= 0 ? "ago" : "from now";
    if (sec < 60) return `${sec}s ${dir}`;
    const m = Math.round(sec / 60);
    if (m < 60) return `${m}m ${dir}`;
    const h = Math.round(m / 60);
    return `${h}h ${dir}`;
  };

  const genId = (p = "id") => `${p}_${crypto.getRandomValues(new Uint32Array(1))[0].toString(16)}`;
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  const isUUID = (s) => /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(s || ""));

  // ========= Notifications =========

  const Notifier = (() => {
    const stack = h("div", { id: "toast-stack", style: { position: "fixed", right: "12px", top: "12px", zIndex: 9999 } });
    document.addEventListener("DOMContentLoaded", () => document.body.appendChild(stack));
    const show = (msg, type = "info", ttl = 4000) => {
      const el = h("div", {
        class: `toast toast-${type}`,
        style: {
          background: type === "error" ? "#fde2e2" : type === "warn" ? "#fff4d6" : "#e6f4ff",
          color: "#000",
          border: "1px solid rgba(0,0,0,.1)",
          borderRadius: "8px",
          padding: "10px 12px",
          marginTop: "8px",
          boxShadow: "0 4px 12px rgba(0,0,0,.08)",
          maxWidth: "420px",
          fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, sans-serif",
          fontSize: "14px",
          lineHeight: "1.4",
        },
      }, String(msg));
      stack.appendChild(el);
      setTimeout(() => el.remove(), ttl);
    };
    return { show };
  })();

  // ========= HTTP Client with retry, ETag cache, abort =========

  class HttpClient {
    constructor({ base, timeoutMs, attempts, baseDelay, maxDelay }) {
      this.base = base.replace(/\/+$/, "");
      this.timeoutMs = timeoutMs;
      this.attempts = attempts;
      this.baseDelay = baseDelay;
      this.maxDelay = maxDelay;
      this._etagCache = new Map(); // key -> { etag, payload, ts }
    }

    _url(path, query) {
      const u = new URL(path.startsWith("/") ? path : `/${path}`, this.base);
      if (query && typeof query === "object") {
        for (const [k, v] of Object.entries(query)) {
          if (v == null || v === "") continue;
          u.searchParams.set(k, String(v));
        }
      }
      return u.toString();
    }

    _headers(extra) {
      const h = new Headers(extra || {});
      if (Config.token) h.set("Authorization", `Bearer ${Config.token}`);
      if (Config.tenant) h.set("X-Tenant-ID", Config.tenant);
      h.set("X-Request-ID", genId("req"));
      h.set("Accept", "application/json");
      return h;
    }

    async _doFetch(url, opts, attempt) {
      const ctrl = new AbortController();
      const to = setTimeout(() => ctrl.abort(`timeout ${this.timeoutMs}ms`), this.timeoutMs);
      try {
        return await fetch(url, { ...opts, signal: ctrl.signal });
      } finally {
        clearTimeout(to);
      }
    }

    async request(path, { method = "GET", query, body, headers, idempotencyKey, preferCacheKey } = {}) {
      const url = this._url(path, query);
      const h = this._headers(headers);
      if (idempotencyKey) h.set("Idempotency-Key", idempotencyKey);

      // ETag: only for GETs
      const cacheKey = preferCacheKey || url;
      if (method === "GET" && this._etagCache.has(cacheKey)) {
        const { etag } = this._etagCache.get(cacheKey);
        if (etag) h.set("If-None-Match", etag);
      }

      let lastErr;
      for (let i = 1; i <= this.attempts; i++) {
        try {
          const res = await this._doFetch(url, {
            method,
            headers: body ? new Headers({ "Content-Type": "application/json", ...Object.fromEntries(h) }) : h,
            body: body ? JSON.stringify(body) : undefined,
          }, i);

          // 304 => return cache
          if (res.status === 304 && method === "GET" && this._etagCache.has(cacheKey)) {
            return { ok: true, status: 200, json: this._etagCache.get(cacheKey).payload, headers: new Headers() };
          }

          if (res.status === 401 || res.status === 403) {
            throw new Error(`auth ${res.status}`);
          }

          const etag = res.headers.get("ETag");
          const text = await res.text();
          const json = text ? JSON.parse(text) : null;

          if (!res.ok) {
            const msg = json?.detail || json?.message || `HTTP ${res.status}`;
            throw new Error(msg);
          }

          if (method === "GET" && etag) {
            this._etagCache.set(cacheKey, { etag, payload: json, ts: Date.now() });
          }

          return { ok: true, status: res.status, json, headers: res.headers };
        } catch (e) {
          lastErr = e;
          if (i >= this.attempts) break;
          const delay = Math.min(this.maxDelay, this.baseDelay * Math.pow(2, i - 1));
          await sleep(Math.random() * delay);
        }
      }
      throw lastErr || new Error("request failed");
    }
  }

  const http = new HttpClient({
    base: Config.apiBase,
    timeoutMs: DEFAULTS.requestTimeoutMs,
    attempts: DEFAULTS.retryAttempts,
    baseDelay: DEFAULTS.retryBaseDelay,
    maxDelay: DEFAULTS.retryMaxDelay,
  });

  // ========= Tiny Router =========

  const Router = (() => {
    const routes = {};
    const root = "#app";
    const go = (path) => history.pushState({}, "", path);
    const on = (path, fn) => { routes[path] = fn; };
    const render = async () => {
      const el = $(root);
      if (!el) return;
      const path = location.hash.replace(/^#/, "") || "/health";
      const fn = routes[path] || routes["/health"];
      el.innerHTML = "";
      try {
        await fn(el);
      } catch (e) {
        el.appendChild(h("div", { class: "error" }, `Render error: ${String(e?.message || e)}`));
      }
    };
    window.addEventListener("popstate", render);
    window.addEventListener("hashchange", render);
    return { on, render, go };
  })();

  // ========= Common Widgets =========

  const HeaderBar = () =>
    h("div", { class: "hdr", style: barStyle() },
      h("div", { style: { display: "flex", gap: "8px", alignItems: "center" } },
        h("strong", {}, "Chronowatch Admin"),
        h("span", { style: { opacity: ".7" } }, "minimal")
      ),
      h("nav", { style: { display: "flex", gap: "12px" } },
        linkBtn("#/health", "Health"),
        linkBtn("#/heartbeats", "Heartbeats"),
        linkBtn("#/latest", "Latest"),
        linkBtn("#/send", "Send HB"),
      ),
      AuthControls()
    );

  function barStyle() {
    return {
      display: "grid",
      gridTemplateColumns: "1fr auto auto",
      gap: "12px",
      padding: "10px 12px",
      borderBottom: "1px solid #eee",
      position: "sticky",
      top: "0",
      backdropFilter: "saturate(180%) blur(8px)",
      background: "rgba(255,255,255,.8)",
      zIndex: 50,
      fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, sans-serif",
    };
  }

  function linkBtn(href, text) {
    return h("a", {
      href,
      style: { textDecoration: "none", padding: "6px 8px", borderRadius: "6px", border: "1px solid #ddd", color: "#111" }
    }, text);
  }

  function AuthControls() {
    const tenantInp = h("input", {
      type: "text",
      placeholder: "Tenant UUID",
      value: Config.tenant,
      style: inputStyle(220),
      oninput: (e) => {
        const v = e.target.value.trim();
        e.target.style.borderColor = isUUID(v) || v === "" ? "#ddd" : "#f66";
      },
    });
    const tokenInp = h("input", { type: "password", placeholder: "Bearer token", value: Config.token, style: inputStyle(220) });
    const apiInp = h("input", { type: "text", placeholder: "API base", value: Config.apiBase, style: inputStyle(220) });
    const save = h("button", { onclick: () => {
      Config.tenant = tenantInp.value.trim();
      Config.token = tokenInp.value.trim();
      Config.apiBase = apiInp.value.trim() || DEFAULTS.apiBase;
      Notifier.show("Saved credentials", "info");
      // re-init client with new base
      http.base = Config.apiBase.replace(/\/+$/, "");
    }}, "Save");
    const clear = h("button", { onclick: () => {
      tokenInp.value = "";
      Config.token = "";
      Notifier.show("Token cleared", "warn");
    }}, "Clear token");
    save.style.marginLeft = "6px";
    clear.style.marginLeft = "6px";
    return h("div", { style: { display: "flex", gap: "6px", alignItems: "center" } }, tenantInp, tokenInp, apiInp, save, clear);
  }

  function inputStyle(w = 160) {
    return { width: `${w}px`, padding: "6px 8px", border: "1px solid #ddd", borderRadius: "6px", fontSize: "14px" };
  }

  const Card = (title, ...children) =>
    h("section", {
      style: {
        border: "1px solid #eee", borderRadius: "12px", padding: "12px",
        boxShadow: "0 2px 12px rgba(0,0,0,.04)", background: "#fff"
      }
    },
      h("div", { style: { fontWeight: "600", marginBottom: "8px" } }, title),
      ...children
    );

  // ========= Views =========

  Router.on("/health", async (root) => {
    root.appendChild(HeaderBar());

    const grid = h("div", { style: { display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px", padding: "12px" } });
    root.appendChild(grid);

    // Liveness
    const liveCard = Card("Liveness /v1/healthz", h("div", {}, "Loading..."));
    grid.appendChild(liveCard);

    // Readiness
    const readyCard = Card("Readiness /v1/readyz", h("div", {}, "Loading..."));
    grid.appendChild(readyCard);

    try {
      const t0 = performance.now();
      const res = await http.request("/v1/healthz");
      const t1 = performance.now();
      liveCard.lastChild.textContent = `Status: ${res.json.status} | ts: ${res.json.ts} | latency: ${Math.round(t1 - t0)}ms`;
    } catch (e) {
      liveCard.lastChild.textContent = `Error: ${String(e.message || e)}`;
    }

    try {
      const t0 = performance.now();
      const res = await http.request("/v1/readyz");
      const t1 = performance.now();
      readyCard.lastChild.textContent = `Status: ${res.json.status} | ts: ${res.json.ts} | latency: ${Math.round(t1 - t0)}ms`;
    } catch (e) {
      readyCard.lastChild.textContent = `Error: ${String(e.message || e)}`;
    }
  });

  Router.on("/heartbeats", async (root) => {
    root.appendChild(HeaderBar());

    const wrap = h("div", { style: { padding: "12px", display: "grid", gap: "12px" } });
    root.appendChild(wrap);

    // Filters
    const serviceInp = h("input", { type: "text", placeholder: "service (optional)", style: inputStyle(240) });
    const instInp = h("input", { type: "text", placeholder: "instance_id (optional)", style: inputStyle(240) });
    const limitInp = h("input", { type: "number", min: "1", max: "500", value: "50", style: inputStyle(100) });
    const btnLoad = h("button", { onclick: () => load() }, "Load");
    const btnClear = h("button", { onclick: () => { tbl.tbody.innerHTML = ""; nextOffset = null; } }, "Clear");

    wrap.appendChild(Card("Filters",
      h("div", { style: { display: "flex", gap: "8px", alignItems: "center", flexWrap: "wrap" } },
        serviceInp, instInp, limitInp, btnLoad, btnClear
      )
    ));

    // Table
    const tbl = makeTable(["ts", "service", "instance_id", "status", "freshness", "id"]);
    wrap.appendChild(Card("Heartbeats", tbl.el));

    let nextOffset = null;

    async function load(offset) {
      try {
        const res = await http.request("/v1/heartbeats", {
          query: {
            service: serviceInp.value.trim() || undefined,
            instance_id: instInp.value.trim() || undefined,
            limit: Number(limitInp.value) || 50,
            offset: offset || undefined,
          }
        });
        const { items, next_offset } = res.json || { items: [], next_offset: null };
        if (!offset) tbl.tbody.innerHTML = "";
        for (const it of items) {
          const freshness = it.ts ? fmtRel(it.ts) : "";
          const row = h("tr", {},
            td(fmtIso(it.ts)),
            td(it.service),
            td(it.instance_id),
            td(it.status),
            td(freshness),
            td(it.id)
          );
          tbl.tbody.appendChild(row);
        }
        nextOffset = next_offset || null;
        pager.textContent = nextOffset ? "Load more…" : "No more";
        pager.disabled = !nextOffset;
      } catch (e) {
        Notifier.show(`Load failed: ${String(e.message || e)}`, "error");
      }
    }

    const pager = h("button", { disabled: true, onclick: () => nextOffset && load(nextOffset) }, "Load more…");
    wrap.appendChild(pager);

    // initial load
    load();
  });

  Router.on("/latest", async (root) => {
    root.appendChild(HeaderBar());
    const wrap = h("div", { style: { padding: "12px", display: "grid", gap: "12px" } });
    root.appendChild(wrap);

    const serviceInp = h("input", { type: "text", placeholder: "service", style: inputStyle(240) });
    const instInp = h("input", { type: "text", placeholder: "instance_id (optional)", style: inputStyle(240) });
    const pollInp = h("input", { type: "number", min: "1000", step: "500", value: Config.latestPollMs, style: inputStyle(140) });
    const btnStart = h("button", {}, "Start");
    const btnStop = h("button", {}, "Stop");

    const info = h("div", { style: { fontFamily: "monospace", whiteSpace: "pre-wrap" } }, "—");
    wrap.appendChild(Card("Latest heartbeat",
      h("div", { style: { display: "flex", gap: "8px", alignItems: "center", flexWrap: "wrap" } },
        serviceInp, instInp, pollInp, btnStart, btnStop
      ),
      info
    ));

    let timer = null;
    let etag = null;

    btnStart.onclick = async () => {
      const service = serviceInp.value.trim();
      if (!service) { Notifier.show("Service is required", "warn"); return; }
      const interval = Math.max(1000, Number(pollInp.value) || Config.latestPollMs);
      Config.latestPollMs = interval;
      if (timer) clearInterval(timer);
      await tick(); // immediate
      timer = setInterval(tick, interval);
    };
    btnStop.onclick = () => { if (timer) clearInterval(timer); timer = null; };

    async function tick() {
      const service = serviceInp.value.trim();
      const instance_id = instInp.value.trim() || undefined;
      try {
        const res = await http.request(`/v1/heartbeats/${encodeURIComponent(service)}/latest`, {
          query: { instance_id },
          headers: etag ? { "If-None-Match": etag } : undefined,
          preferCacheKey: `latest:${service}:${instance_id || ""}`,
        });
        if (res.headers?.get) {
          const newEtag = res.headers.get("ETag");
          if (newEtag) etag = newEtag.replace(/^W\//, "");
        }
        const obj = res.json || {};
        const latest = obj.latest;
        const freshness = typeof obj.freshness_seconds === "number" ? `${obj.freshness_seconds}s` : "n/a";
        info.textContent = latest ? [
          `service: ${obj.service}`,
          `instance_id: ${obj.instance_id || "(any)"}`,
          `status: ${latest.status}`,
          `ts: ${fmtIso(latest.ts)} (${freshness} old)`,
          `received_at: ${fmtIso(latest.received_at)}`,
          `id: ${latest.id}`,
        ].join("\n") : "No data";
      } catch (e) {
        info.textContent = `Error: ${String(e.message || e)}`;
      }
    }
  });

  Router.on("/send", async (root) => {
    root.appendChild(HeaderBar());

    const wrap = h("div", { style: { padding: "12px", display: "grid", gap: "12px" } });
    root.appendChild(wrap);

    const service = h("input", { type: "text", placeholder: "service", style: inputStyle(240) });
    const instance = h("input", { type: "text", placeholder: "instance_id", style: inputStyle(240) });
    const status = h("select", { style: inputStyle(160) },
      h("option", { value: "ok" }, "ok"),
      h("option", { value: "degraded" }, "degraded"),
      h("option", { value: "down" }, "down"),
    );
    const ts = h("input", { type: "datetime-local", style: inputStyle(220) });
    const details = h("textarea", { placeholder: '{"key":"value"}', style: { ...inputStyle(480), height: "120px" } });

    const idem = h("input", { type: "text", placeholder: "Idempotency-Key (optional)", style: inputStyle(240) });
    const submit = h("button", { onclick: onSubmit }, "Send heartbeat");

    wrap.appendChild(Card("Send Heartbeat (diagnostic)",
      h("div", { style: { display: "grid", gap: "8px", maxWidth: "820px" } },
        labelWrap("Service", service),
        labelWrap("Instance", instance),
        labelWrap("Status", status),
        labelWrap("Timestamp (local)", ts),
        labelWrap("Details JSON", details),
        labelWrap("Idempotency-Key", idem),
        submit
      )
    ));

    const out = h("pre", { style: { background: "#fafafa", border: "1px solid #eee", borderRadius: "8px", padding: "10px", overflow: "auto" } }, "—");
    wrap.appendChild(Card("Response", out));

    async function onSubmit() {
      const svc = service.value.trim();
      const inst = instance.value.trim();
      if (!svc || !inst) { Notifier.show("Service and instance are required", "warn"); return; }
      let tsVal = ts.value ? new Date(ts.value) : new Date();
      const payload = {
        service: svc,
        instance_id: inst,
        status: status.value,
        ts: tsVal.toISOString(),
        details: safeParseJSON(details.value.trim(), {}),
      };
      try {
        const res = await http.request("/v1/heartbeats", {
          method: "POST",
          body: payload,
          idempotencyKey: idem.value.trim() || undefined,
        });
        out.textContent = JSON.stringify(res.json, null, 2);
        Notifier.show("Heartbeat sent", "info");
      } catch (e) {
        out.textContent = `Error: ${String(e.message || e)}`;
        Notifier.show(`Send failed: ${String(e.message || e)}`, "error");
      }
    }
  });

  function labelWrap(lbl, el) {
    return h("label", { style: { display: "grid", gap: "4px" } }, h("span", { style: { fontSize: "12px", color: "#555" } }, lbl), el);
  }

  function makeTable(headers) {
    const thead = h("thead", {},
      h("tr", {}, ...headers.map((k) => h("th", {
        style: thStyle(),
        onclick: () => sortBy(k),
      }, k)))
    );
    const tbody = h("tbody", {});
    const tbl = h("table", {
      style: { width: "100%", borderCollapse: "collapse", tableLayout: "fixed" }
    }, thead, tbody);
    const state = { sortKey: headers[0], asc: false };

    function sortBy(k) {
      state.asc = state.sortKey === k ? !state.asc : true;
      state.sortKey = k;
      const idx = headers.indexOf(k);
      const rows = Array.from(tbody.querySelectorAll("tr"));
      rows.sort((a, b) => {
        const ta = a.children[idx].textContent || "";
        const tb = b.children[idx].textContent || "";
        const na = Number(ta), nb = Number(tb);
        const va = Number.isFinite(na) ? na : ta;
        const vb = Number.isFinite(nb) ? nb : tb;
        if (va < vb) return state.asc ? -1 : 1;
        if (va > vb) return state.asc ? 1 : -1;
        return 0;
      });
      tbody.innerHTML = "";
      rows.forEach((r) => tbody.appendChild(r));
    }

    return { el: tbl, tbody, sortBy };
  }

  function thStyle() {
    return { textAlign: "left", borderBottom: "1px solid #eee", padding: "8px", cursor: "pointer" };
  }
  function td(content) {
    return h("td", { style: { padding: "8px", borderBottom: "1px solid #f3f3f3", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" } }, String(content ?? ""));
  }

  function safeParseJSON(s, fallback) {
    if (!s) return fallback;
    try { return JSON.parse(s); } catch { return fallback; }
  }

  // ========= App bootstrap =========

  async function init() {
    const root = $("#app") || document.body.appendChild(h("div", { id: "app" }));
    root.innerHTML = "";
    document.body.style.margin = "0";
    document.body.style.background = "#f7f9fb";

    // Top-level layout grid
    const container = h("div", { style: { maxWidth: "1200px", margin: "0 auto" } });
    const hdr = HeaderBar();
    const main = h("main", {});
    container.appendChild(hdr);
    container.appendChild(main);
    root.appendChild(container);

    // Basic guardrails
    if (Config.apiBase !== http.base) http.base = Config.apiBase.replace(/\/+$/, "");
    if (Config.tenant && !isUUID(Config.tenant)) {
      Notifier.show("Tenant should be UUID", "warn");
    }

    await Router.render();
  }

  document.addEventListener("DOMContentLoaded", init);
})();
