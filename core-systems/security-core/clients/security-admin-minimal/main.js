// file: clients/security-admin-minimal/main.js
// Security Admin Minimal - single-file SPA (no deps)
// Hard requirements: modern browsers (ES2021+), served over HTTPS.
// This file intentionally does not touch innerHTML with untrusted data.

// ===== Strict mode ===========================================================
"use strict";

// ===== Runtime config ========================================================
// Configure via window.SECURITY_ADMIN_CONFIG before this script loads, e.g.:
// <script>window.SECURITY_ADMIN_CONFIG={ apiBaseUrl:"/api/v1", oidc:{ issuer:"https://idp.example", clientId:"sec-admin", redirectUri:location.origin+"/", scope:"openid profile offline_access" }, telemetry:{enabled:true} };</script>
const DEFAULT_CONFIG = Object.freeze({
  apiBaseUrl: "/api/v1",
  requestTimeoutMs: 8000,
  retry: { attempts: 3, backoffMs: 200, maxBackoffMs: 2000 },
  oidc: null, // {issuer, clientId, redirectUri, scope, audience?}
  auditSseUrl: null, // e.g. "/api/v1/audit/stream"
  telemetry: { enabled: true, app: "security-admin-minimal", version: "1.0.0" }
});
const CFG = deepFreeze(merge({}, DEFAULT_CONFIG, window.SECURITY_ADMIN_CONFIG || {}));

// ===== Small stdlib ==========================================================
function deepFreeze(o){Object.freeze(o);Object.getOwnPropertyNames(o).forEach(p=>{const v=o[p];if(v&&typeof v==="object"&&!Object.isFrozen(v))deepFreeze(v);});return o;}
function merge(dst,...srcs){for(const s of srcs){if(!s)continue;for(const k of Object.keys(s)){const v=s[k];if(v&&typeof v==="object"&&!Array.isArray(v)){dst[k]=merge(dst[k]||{},v);}else{dst[k]=v;}}}return dst;}
function sleep(ms){return new Promise(r=>setTimeout(r,ms));}
function b64url(buf){return btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");}
function text(node, s){node.textContent = s ?? "";}
function byId(id){return /** @type {HTMLElement} */(document.getElementById(id));}
function el(tag, attrs={}, children=[]){const n=document.createElement(tag);for(const[k,v]of Object.entries(attrs)){if(k==="class")n.className=v; else if(k.startsWith("on")&&typeof v==="function") n.addEventListener(k.slice(2),v); else n.setAttribute(k,String(v));}for(const c of [].concat(children)){if(c==null)continue;if(typeof c==="string")n.appendChild(document.createTextNode(c)); else n.appendChild(c);}return n;}
function randStr(len=32){const a=new Uint8Array(len);crypto.getRandomValues(a);return b64url(a).slice(0,len);}
async function sha256(input){const data=typeof input==="string"?new TextEncoder().encode(input):input;return new Uint8Array(await crypto.subtle.digest("SHA-256",data));}
function nowIso(){return new Date().toISOString().replace(/\.\d{3}Z$/,"Z");}
function redact(s, keep=4){if(!s)return "";return s.length<=2*keep?"****":s.slice(0,keep)+"…"+s.slice(-keep);}

// ===== Telemetry (best-effort, no PII) ======================================
function logEvent(type, data={}){ if(!CFG.telemetry?.enabled) return;
  console.debug("[telemetry]", type, data);
}

// ===== Auth session (tokens only in memory + sessionStorage) ================
const Auth = (function(){
  let state = { accessToken:null, refreshToken:null, idToken:null, tokenType:"Bearer", expiresAt:0, oidc:null };
  const KEY = "secadmin.auth.v1";

  function load(){
    try{const raw=sessionStorage.getItem(KEY); if(!raw) return;
      const v=JSON.parse(raw); state={...state,...v};}catch{}
  }
  function save(){
    const toStore = { ...state, accessToken: null, idToken: null }; // do NOT persist AT/IDT
    sessionStorage.setItem(KEY, JSON.stringify(toStore));
  }
  function setTokens({accessToken, refreshToken, idToken, tokenType="Bearer", expiresInSec=3600, oidc=null}){
    state.accessToken = accessToken || null;
    state.refreshToken = refreshToken || null;
    state.idToken = idToken || null;
    state.tokenType = tokenType;
    state.expiresAt = Date.now() + Math.max(10, expiresInSec-5)*1000;
    if(oidc) state.oidc = oidc;
    save();
  }
  function clear(){ state={ accessToken:null, refreshToken:null, idToken:null, tokenType:"Bearer", expiresAt:0, oidc:null }; save(); }
  function isExpired(leewayMs=5000){ return !state.accessToken || Date.now()+leewayMs >= state.expiresAt; }
  function get(){ return { ...state }; }
  function setManualBearer(token){ setTokens({accessToken: token, refreshToken: null, idToken: null, tokenType:"Bearer", expiresInSec: 3600}); }
  load();
  return { setTokens, clear, isExpired, get, setManualBearer };
})();

// ===== OIDC PKCE (optional) =================================================
const OIDC = (function(){
  async function startLogin(){
    if(!CFG.oidc) throw new Error("OIDC not configured");
    const state = randStr(32);
    const verifier = randStr(64);
    const challenge = b64url(await sha256(verifier));
    sessionStorage.setItem("secadmin.pkce", JSON.stringify({ state, verifier, ts: Date.now() }));
    const p = new URLSearchParams({
      client_id: CFG.oidc.clientId,
      redirect_uri: CFG.oidc.redirectUri || location.origin + location.pathname,
      response_type: "code",
      scope: CFG.oidc.scope || "openid profile",
      state, code_challenge: challenge, code_challenge_method: "S256",
      ...(CFG.oidc.audience ? { audience: CFG.oidc.audience } : {})
    });
    const authzUrl = (CFG.oidc.authorizationEndpoint || (CFG.oidc.issuer.replace(/\/+$/,"") + "/protocol/openid-connect/auth"));
    location.assign(authzUrl + "?" + p.toString());
  }
  async function exchangeCode(urlParams){
    const pk = JSON.parse(sessionStorage.getItem("secadmin.pkce")||"null");
    if(!pk || !urlParams.get("code") || urlParams.get("state")!==pk.state) throw new Error("PKCE state invalid");
    const code = urlParams.get("code");
    const tokenUrl = (CFG.oidc.tokenEndpoint || (CFG.oidc.issuer.replace(/\/+$/,"") + "/protocol/openid-connect/token"));
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code, client_id: CFG.oidc.clientId,
      redirect_uri: CFG.oidc.redirectUri || location.origin + location.pathname,
      code_verifier: pk.verifier
    });
    const res = await fetch(tokenUrl, { method:"POST", headers:{ "Content-Type":"application/x-www-form-urlencoded" }, body });
    if(!res.ok) throw new Error("OIDC token exchange failed: "+res.status);
    const t = await res.json();
    Auth.setTokens({
      accessToken: t.access_token,
      refreshToken: t.refresh_token || null,
      idToken: t.id_token || null,
      tokenType: t.token_type || "Bearer",
      expiresInSec: t.expires_in || 3600,
      oidc: { issuer: CFG.oidc.issuer, clientId: CFG.oidc.clientId }
    });
    history.replaceState({}, document.title, location.origin + location.pathname + location.search.replace(/\??code=[^&]+&?/, "").replace(/\??state=[^&]+&?/, ""));
  }
  async function refresh(){
    const s = Auth.get();
    if(!s.refreshToken) throw new Error("No refresh token");
    const tokenUrl = (CFG.oidc.tokenEndpoint || (CFG.oidc.issuer.replace(/\/+$/,"") + "/protocol/openid-connect/token"));
    const body = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: s.refreshToken,
      client_id: CFG.oidc.clientId
    });
    const res = await fetch(tokenUrl, { method:"POST", headers:{ "Content-Type":"application/x-www-form-urlencoded" }, body });
    if(!res.ok) throw new Error("OIDC refresh failed: "+res.status);
    const t = await res.json();
    Auth.setTokens({
      accessToken: t.access_token, refreshToken: t.refresh_token || s.refreshToken,
      idToken: t.id_token || s.idToken, tokenType: t.token_type || "Bearer",
      expiresInSec: t.expires_in || 3600
    });
  }
  return { startLogin, exchangeCode, refresh };
})();

// ===== API client with safeFetch ============================================
const Api = (function(){
  function headers(extra={}, etag=null, idempotencyKey=null){
    const s = Auth.get();
    const h = { "Accept":"application/json", "X-Request-ID": crypto.randomUUID(), "X-Client": `${CFG.telemetry.app}/${CFG.telemetry.version}` };
    if(s.accessToken) h["Authorization"] = `${s.tokenType} ${s.accessToken}`;
    if(etag) h["If-Match"] = etag;
    if(idempotencyKey) h["Idempotency-Key"] = idempotencyKey;
    return Object.assign(h, extra);
  }

  async function safeFetch(path, { method="GET", json=null, query=null, etag=null, idempotency=false, timeoutMs=CFG.requestTimeoutMs }={}){
    const ctrl = new AbortController();
    const t = setTimeout(()=>ctrl.abort("timeout"), Math.max(1000, timeoutMs));
    try{
      const qs = query ? ("?"+new URLSearchParams(query).toString()) : "";
      const url = (path.startsWith("http")? path : (CFG.apiBaseUrl.replace(/\/+$/,"") + "/" + path.replace(/^\/+/,""))) + qs;
      const key = idempotency ? (crypto.randomUUID()) : null;
      const body = json!=null ? JSON.stringify(json) : undefined;
      const hdrs = headers(json!=null?{"Content-Type":"application/json"}:{}, etag, key);
      let attempt = 0, backoff = CFG.retry.backoffMs;
      while(true){
        attempt++;
        const resp = await fetch(url, { method, headers: hdrs, body, signal: ctrl.signal, cache:"no-store", credentials:"include" });
        if(resp.status===401 && CFG.oidc && Auth.get().refreshToken){
          try{ await OIDC.refresh(); hdrs["Authorization"] = `${Auth.get().tokenType} ${Auth.get().accessToken}`; continue; }catch{}
        }
        if(resp.status>=500 && attempt<CFG.retry.attempts){
          await sleep(Math.min(backoff, CFG.retry.maxBackoffMs)); backoff*=2; continue;
        }
        const et = resp.headers.get("ETag");
        let data = null;
        if(resp.status!==204){
          const ct = resp.headers.get("Content-Type")||"";
          data = ct.includes("application/json") ? await resp.json() : await resp.text();
        }
        if(!resp.ok){ throw Object.assign(new Error(`HTTP ${resp.status}`), { status: resp.status, data }); }
        return { data, etag: et, status: resp.status };
      }
    } finally { clearTimeout(t); }
  }

  return { safeFetch };
})();

// ===== Router ================================================================
const Router = (function(){
  const routes = {};
  function on(path, handler){ routes[path]=handler; }
  async function go(path){ location.hash = "#"+path; }
  async function dispatch(){
    const raw = location.hash.replace(/^#/,"").trim();
    const [path, qs] = raw.split("?");
    const params = new URLSearchParams(qs||"");
    if(routes[path||""]){ await routes[path||""](params); }
    else if(routes["404"]){ await routes["404"](params, path); }
  }
  window.addEventListener("hashchange", dispatch);
  return { on, go, dispatch };
})();

// ===== UI skeleton ===========================================================
const App = (function(){
  const root = document.body;
  function layout(){
    document.body.innerHTML="";
    const nav = el("nav", {class:"nav"});
    const title = el("strong",{},["Security Admin"]);
    const links = el("div", {class:"links"}, [
      aLink("Dashboard","#"),
      aLink("Users","#users"),
      aLink("Tokens","#tokens"),
      aLink("Policies","#policies"),
      aLink("Audit","#audit"),
      el("button",{id:"btnLogout",onclick:logout, "aria-label":"Logout"},["Logout"])
    ]);
    nav.append(title,links);
    const main = el("main",{id:"app"});
    document.body.append(nav, main);
  }
  function aLink(name, href){ const a=el("a",{href}); text(a,name); a.addEventListener("click",(e)=>{ if(a.getAttribute("href").startsWith("#")){ e.preventDefault(); Router.go(a.getAttribute("href").slice(1)); }}); return a; }
  function logout(){
    Auth.clear();
    sessionStorage.removeItem("secadmin.pkce");
    Router.go("login");
  }
  function mount(vnode){ const app = byId("app"); app.innerHTML=""; app.appendChild(vnode); }
  return { layout, mount, logout };
})();

// ===== Pages ================================================================
const Pages = (function(){
  function requireAuth(){ const s=Auth.get(); if(!s.accessToken){ Router.go("login"); return false; } return true; }

  // --- Login ---
  async function Login(){
    const wrap = el("div",{class:"page"},[
      el("h2",{},["Login"]),
      CFG.oidc ? el("button",{id:"btnOidc"},["Sign in with Identity Provider"]) : el("div"),
      el("details",{},[
        el("summary",{},["Use temporary token"]),
        el("div",{},[
          el("label",{},["Bearer token"]),
          el("input",{id:"tok",type:"password",autocomplete:"off",placeholder:"Paste token"}),
          el("button",{id:"btnTok"},["Continue"])
        ])
      ])
    ]);
    wrap.querySelector("#btnOidc")?.addEventListener("click", async()=>{ try{ await OIDC.startLogin(); }catch(e){ alert(e.message); } });
    wrap.querySelector("#btnTok")?.addEventListener("click", ()=>{ const v=wrap.querySelector("#tok").value.trim(); if(v){ Auth.setManualBearer(v); Router.go(""); } });
    App.mount(wrap);
  }

  // --- Dashboard ---
  async function Dashboard(){
    if(!requireAuth()) return;
    const card = el("div",{class:"page"},[
      el("h2",{},["Dashboard"]),
      el("div",{id:"stat"},["Loading…"])
    ]);
    App.mount(card);
    try{
      const me = await Api.safeFetch("me");
      const sys = await Api.safeFetch("system/health");
      const stat = byId("stat"); stat.innerHTML="";
      stat.append(
        kv("User", (me.data?.username||me.data?.email||"-")),
        kv("Tenant", me.data?.tenant_id || "-"),
        kv("Health", JSON.stringify(sys.data))
      );
    }catch(e){
      renderError(card, e);
    }
  }

  // --- Users (cursor pagination) ---
  async function Users(params){
    if(!requireAuth()) return;
    const q = Object.fromEntries(params.entries());
    const pageSize = q.ps || 20;
    const page = el("div",{class:"page"},[
      el("h2",{},["Users"]),
      el("div",{id:"toolbar"},[
        el("input",{id:"search",placeholder:"search text (username/email/display_name)"}),
        el("button",{id:"btnSearch"},["Search"]),
        el("button",{id:"btnCreate"},["Create user"])
      ]),
      el("table",{class:"grid","aria-label":"Users table"},
        [thead(["ID","Username","Email","Roles","Disabled","Created","Actions"]), el("tbody",{id:"grid"})]
      ),
      el("div",{id:"pager"},[
        el("button",{id:"btnMore"},["Load more"])
      ])
    ]);
    App.mount(page);
    const state = { cursor: q.cur || null, text:q.text||null, items:[] };

    async function loadMore(reset=false){
      try{
        const query = { page_size: pageSize };
        if(state.cursor) query.page_cursor = state.cursor;
        if(state.text) query.text = state.text;
        const res = await Api.safeFetch("users", { query });
        state.cursor = res.data?.next_page_cursor || null;
        for(const u of res.data?.items||[]){ state.items.push(u); }
        renderRows(state.items);
        byId("btnMore").disabled = !state.cursor;
      }catch(e){ renderError(page,e); }
    }
    function renderRows(items){
      const tb = byId("grid"); tb.innerHTML="";
      for(const u of items){
        const tr = el("tr",{},[
          td(u.id), td(u.username||"-"), td(u.email||"-"),
          td((u.roles||[]).join(",")), td(String(u.disabled)),
          td(u.created_at||"-"),
          tdBtn("Edit", ()=>editUser(u))
        ]);
        tb.appendChild(tr);
      }
    }
    async function editUser(u){
      const dlg = modal("Edit user", form([
        ["Username", "username", u.username||""],
        ["Email", "email", u.email||""],
        ["Display name","display_name", u.display_name||""],
        ["Disabled","disabled", String(u.disabled)]
      ], "Save"));
      dlg.onconfirm = async (vals)=>{
        try{
          const patch = { username:vals.username||null, email:vals.email||null, display_name:vals.display_name||null, disabled: vals.disabled==="true" };
          const res = await Api.safeFetch(`users/${encodeURIComponent(u.id)}`, { method:"PATCH", json:patch, etag:u.version!=null?`W/"${u.version}"`:null });
          alert("Saved");
          Router.dispatch(); // reload page
        }catch(e){ alert(e.message); }
      };
    }
    byId("btnSearch").addEventListener("click", ()=>{ state.items=[]; state.cursor=null; state.text=byId("search").value||null; loadMore(true); });
    byId("btnCreate").addEventListener("click", ()=>{
      const dlg = modal("Create user", form([
        ["Username", "username",""],["Email","email",""],["Display name","display_name",""]
      ], "Create"));
      dlg.onconfirm = async (vals)=>{
        try{
          const res = await Api.safeFetch("users", { method:"POST", json:{ username: vals.username||null, email: vals.email||null, display_name: vals.display_name||null }, idempotency:true });
          alert("Created: "+res.data.id);
          Router.dispatch();
        }catch(e){ alert(e.message); }
      };
    });
    byId("btnMore").addEventListener("click", ()=>loadMore());
    loadMore();
  }

  // --- Tokens (issue/revoke) ---
  async function Tokens(){
    if(!requireAuth()) return;
    const page = el("div",{class:"page"},[
      el("h2",{},["Tokens"]),
      el("div",{class:"row"},[
        el("button",{id:"btnIssue"},["Issue token"]),
        el("button",{id:"btnList"},["Refresh list"])
      ]),
      el("table",{class:"grid"},[ thead(["ID","Subject","Scope","Expires","Actions"]), el("tbody",{id:"tlist"}) ])
    ]);
    App.mount(page);

    async function list(){ try{
      const res = await Api.safeFetch("tokens", { query:{ limit:50 }});
      const tb = byId("tlist"); tb.innerHTML="";
      for(const t of (res.data?.items||[])){
        const tr = el("tr",{},[
          td(t.id), td(t.subject||"-"), td((t.scopes||[]).join(" ")), td(t.expires_at||"-"),
          tdBtn("Revoke", ()=>revoke(t.id))
        ]);
        tb.appendChild(tr);
      }
    }catch(e){ renderError(page,e); } }
    async function issue(){
      const dlg = modal("Issue token", form([["Subject","subject",""],["Scope (space separated)","scope",""]],"Issue"));
      dlg.onconfirm = async(v)=>{
        try{
          const res = await Api.safeFetch("tokens", { method:"POST", json:{ subject:v.subject, scope: v.scope? v.scope.split(/\s+/):[] }, idempotency:true });
          alert("Token: " + redact(res.data?.token||"", 8));
          list();
        }catch(e){ alert(e.message); }
      };
    }
    async function revoke(id){
      if(!confirm("Revoke token "+id+"?")) return;
      try{ await Api.safeFetch(`tokens/${encodeURIComponent(id)}`, { method:"DELETE", idempotency:true }); list(); }catch(e){ alert(e.message); }
    }

    byId("btnIssue").addEventListener("click", issue);
    byId("btnList").addEventListener("click", list);
    list();
  }

  // --- Policies (read-only minimal) ---
  async function Policies(){
    if(!requireAuth()) return;
    const page = el("div",{class:"page"},[
      el("h2",{},["Policies"]),
      el("div",{class:"row"},[ el("button",{id:"btnReload"},["Reload"]) ]),
      el("ul",{id:"plist"}), el("pre",{id:"pjson","aria-live":"polite"})
    ]);
    App.mount(page);
    async function load(){
      try{
        const ids = await Api.safeFetch("authz/policies/ids");
        const ul = byId("plist"); ul.innerHTML="";
        for(const pid of (ids.data||[])){
          const li = el("li",{},[ el("a",{href:"#",onclick:(e)=>{e.preventDefault();show(pid);} },[pid]) ]);
          ul.appendChild(li);
        }
      }catch(e){ renderError(page,e); }
    }
    async function show(id){
      try{
        const p = await Api.safeFetch(`authz/policies/${encodeURIComponent(id)}`);
        const pre = byId("pjson"); pre.textContent = JSON.stringify(p.data,null,2);
      }catch(e){ renderError(page,e); }
    }
    byId("btnReload").addEventListener("click", load);
    load();
  }

  // --- Audit (SSE viewer) ---
  async function Audit(){
    if(!requireAuth()) return;
    const page = el("div",{class:"page"},[
      el("h2",{},["Audit stream"]),
      el("div",{},["Live (server-sent events)."]),
      el("pre",{id:"alog",style:"max-height:50vh;overflow:auto;background:#111;color:#0f0;padding:8px"})
    ]);
    App.mount(page);
    const url = CFG.auditSseUrl || (CFG.apiBaseUrl.replace(/\/+$/,"") + "/audit/stream");
    try{
      const hdrs = {}; const s=Auth.get(); if(s.accessToken) hdrs["Authorization"]=`${s.tokenType} ${s.accessToken}`;
      const es = new EventSource(url + (url.includes("?")?"&":"?") + "x="+encodeURIComponent(crypto.randomUUID()), { withCredentials:true });
      const log = byId("alog");
      es.onmessage = (ev)=>{ const t = nowIso()+" "+ev.data+"\n"; log.appendChild(document.createTextNode(t)); log.scrollTop=log.scrollHeight; };
      es.onerror = ()=>{ es.close(); log.appendChild(document.createTextNode(nowIso()+" [error]\n")); };
    }catch(e){ renderError(page,e); }
  }

  // helpers
  function kv(k,v){ return el("div",{class:"kv"},[el("strong",{},[k+": "]), el("span",{},[typeof v==="string"?v:JSON.stringify(v)])]);}
  function thead(cols){ const tr=el("tr"); for(const c of cols) tr.appendChild(el("th",{},[c])); return el("thead",{},[tr]); }
  function td(v){ return el("td",{},[String(v??"")]); }
  function tdBtn(label, onClick){ return el("td",{},[ el("button",{onclick:onClick},[label]) ]); }

  function form(fields, submitLabel){
    const f = el("form",{class:"form", onsubmit:(e)=>{e.preventDefault();} },[]);
    for(const [label,name,value] of fields){
      const row = el("div",{class:"row"},[
        el("label",{"for":name},[label]),
        el("input",{id:name,name,type:"text",value: value??""})
      ]);
      f.appendChild(row);
    }
    f.appendChild(el("button",{type:"submit"},[submitLabel]));
    return f;
  }
  function modal(title, content){
    const dlg = el("dialog",{open:"open"},[
      el("h3",{},[title]), content, el("div",{class:"row"},[
        el("button",{id:"ok"},["OK"]), el("button",{id:"cancel"},["Cancel"])
      ])
    ]);
    document.body.appendChild(dlg);
    dlg.querySelector("#cancel").addEventListener("click",()=>{ dlg.remove(); });
    dlg.querySelector("form button[type=submit]")?.addEventListener("click",(e)=>{ e.preventDefault(); dlg.querySelector("#ok").click(); });
    dlg.querySelector("#ok").addEventListener("click",()=>{ const vals={}; dlg.querySelectorAll("input").forEach(i=>vals[i.name]=i.value); dlg.onconfirm?.(vals); dlg.remove(); });
    return dlg;
  }
  function renderError(host, e){
    const box = el("div",{class:"error","role":"alert"});
    const status = e?.status? `HTTP ${e.status}`:"";
    const body = typeof e?.data==="string"? e.data : (e?.data? JSON.stringify(e.data): "");
    box.append(el("strong",{},["Error: "]), document.createTextNode(e?.message||"unknown"));
    if(status) box.append(el("div",{},[status]));
    if(body) box.append(el("pre",{},[body]));
    host.appendChild(box);
  }

  return { Login, Dashboard, Users, Tokens, Policies, Audit };
})();

// ===== Bootstrapping ========================================================
(async function bootstrap(){
  // Basic layout
  App.layout();

  // OIDC code exchange if returned from IdP
  const urlParams = new URLSearchParams(location.search);
  if(urlParams.get("code") && CFG.oidc){
    try{ await OIDC.exchangeCode(urlParams); }catch(e){ console.error(e); alert("OIDC error: "+e.message); }
  }

  // Routes
  Router.on("", Pages.Dashboard);
  Router.on("login", Pages.Login);
  Router.on("users", Pages.Users);
  Router.on("tokens", Pages.Tokens);
  Router.on("policies", Pages.Policies);
  Router.on("audit", Pages.Audit);
  Router.on("404", async(_,path)=>{ App.mount(el("div",{class:"page"},[el("h2",{},["Not found"]), el("div",{},["Route: ", path||"/"]) ])); });

  // If not authenticated, go to login
  if(!Auth.get().accessToken && !location.hash) location.hash="#login";
  await Router.dispatch();
})().catch(e=>{ console.error(e); alert(e.message); });

// ===== Minimal styles (optional inline, can be removed if using CSS file) ===
// Kept for usability; no external CSS required.
(function style(){
  const css = `
  body { font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Arial; margin:0; background:#f7f7f8; color:#1b1f23; }
  nav { display:flex; justify-content:space-between; align-items:center; padding:10px 14px; background:#0f172a; color:#fff; position:sticky; top:0; }
  nav .links a, nav .links button { margin-left:10px; color:#fff; text-decoration:none; background:transparent; border:1px solid #334155; padding:6px 10px; border-radius:6px; cursor:pointer; }
  main#app { padding:16px; }
  .page h2 { margin-top:0; }
  .grid { width:100%; border-collapse:collapse; background:#fff; }
  .grid th, .grid td { border:1px solid #e5e7eb; padding:6px 8px; text-align:left; }
  .row { margin:8px 0; display:flex; gap:8px; align-items:center; }
  input[type=text], input[type=password] { padding:6px 8px; border:1px solid #cbd5e1; border-radius:6px; min-width:240px; }
  button { padding:6px 10px; border-radius:6px; border:1px solid #cbd5e1; background:#fff; cursor:pointer; }
  dialog { border:none; border-radius:8px; padding:12px; }
  .error { background:#fee2e2; border:1px solid #ef4444; color:#991b1b; padding:8px; border-radius:6px; margin-top:10px; }
  `;
  const s = document.createElement("style"); s.textContent = css; document.head.appendChild(s);
})();
