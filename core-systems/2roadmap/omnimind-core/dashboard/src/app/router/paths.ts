/* core-systems/omnimind-core/dashboard/src/app/router/paths.ts
 * Industrial-grade typed route registry for React/Vite apps.
 * - Type-safe params, query, and hash building
 * - Minimal pattern matcher (no external deps)
 * - Stable singleton across HMR
 * - Immutable route registry
 */

//////////////////// Utility types ////////////////////

type Dict<T = unknown> = Record<string, T>;
type QueryValue = string | number | boolean | null | undefined | (string | number | boolean)[];

/** Convert allowed query object to URLSearchParams */
function toSearchParams(query?: Dict<QueryValue>): URLSearchParams {
  const sp = new URLSearchParams();
  if (!query) return sp;

  for (const [k, v] of Object.entries(query)) {
    if (v === undefined) continue;
    if (v === null) {
      sp.append(k, "");
      continue;
    }
    if (Array.isArray(v)) {
      for (const x of v) sp.append(k, String(x));
    } else {
      sp.set(k, String(v));
    }
  }
  return sp;
}

function encodeSegment(val: string | number | boolean): string {
  return encodeURIComponent(String(val));
}

//////////////////// Route registry core ////////////////////

/**
 * Route pattern syntax (subset similar to path-to-regexp):
 *  - Static: /dashboard/settings
 *  - Param: /project/:projectId
 *  - Optional param segment suffix "?": /search/:tab?
 *  - Wildcard (splat) at the end: /* or /files/* to catch rest (returns key "*")
 */
type Pattern = `/${string}`;

export type RouteSpec<
  Params extends Dict<string> = Dict<string>,
  Query extends Dict<QueryValue> | undefined = undefined
> = {
  /** Unique route name */
  name: string;
  /** Pattern with :params and optional ? */
  pattern: Pattern;
  /** Default query appended if not overridden */
  defaults?: Query;
};

type InferParams<P extends Pattern> =
  P extends `${string}:${infer Key}?${infer Tail}`
    ? { [k in Key | keyof InferParams<`/${Tail}`>]: string }
    : P extends `${string}:${infer Key}/${infer Tail}`
      ? { [k in Key | keyof InferParams<`/${Tail}`>]: string }
      : P extends `${string}*${infer _Tail}`
        ? { "*"?: string }
        : {};

type StaticOrNever<T> = keyof T extends never ? {} : T;

export type RouteDef<P extends Pattern, Q extends Dict<QueryValue> | undefined = undefined> =
  RouteSpec<StaticOrNever<InferParams<P>>, Q>;

export type RouteInstance<
  P extends Dict<string> = Dict<string>,
  Q extends Dict<QueryValue> | undefined = undefined
> = {
  name: string;
  pattern: Pattern;
  build: (params: P, options?: { query?: Q; hash?: string }) => string;
};

//////////////////// Pattern compiler & matcher ////////////////////

type Compiled = {
  name: string;
  pattern: Pattern;
  keys: string[]; // param keys incl. optional
  regex: RegExp;
  hasSplat: boolean;
};

function compilePattern(name: string, pattern: Pattern): Compiled {
  // Normalize multiple slashes and trim trailing slash (except root)
  const normalized = (pattern === "/" ? "/" : pattern.replace(/\/{2,}/g, "/").replace(/\/+$/, "")) as Pattern;

  // Tokenize :param and :param?; capture splat "/*" at end
  const keys: string[] = [];
  let hasSplat = false;

  // Escape regex specials except '/'
  const esc = (s: string) => s.replace(/([.+^=!:${}()|[\]\\])/g, "\\$1");

  let rx = "^";
  const segs = normalized.split("/").filter((s, i) => !(i === 0 && s === "")); // remove leading empty from split

  if (segs.length === 0) {
    rx += "\\/?$";
  } else {
    for (let i = 0; i < segs.length; i++) {
      const seg = segs[i];
      rx += "\\/"; // leading slash for each segment

      if (seg === "*") {
        hasSplat = true;
        keys.push("*");
        rx += "(.*)"; // greedy to end
        break; // splat must be terminal
      }

      // :param or :param?
      const m = /^:([A-Za-z0-9_]+)(\?)?$/.exec(seg);
      if (m) {
        const key = m[1];
        const optional = Boolean(m[2]);
        keys.push(key);
        if (optional) {
          // Optional segment including preceding slash; allow missing
          rx = rx.replace(/\\\/$/, ""); // remove last added slash
          rx += "(?:\\/([^\\/]+))?"; // whole '/value' optional
        } else {
          rx += "([^\\/]+)";
        }
        continue;
      }

      // static segment
      rx += esc(seg);
    }
    rx += "\\/?$";
  }

  const regex = new RegExp(rx);
  return { name, pattern: normalized, keys, regex, hasSplat };
}

function interpolate(pattern: Pattern, params: Dict<string>): string {
  if (pattern === "/") return "/";
  let out = pattern;

  // Replace params
  out = out.replace(/:([A-Za-z0-9_]+)\??/g, (_, key: string) => {
    const v = params[key];
    if (v === undefined || v === null || v === "") {
      // Optional segments like ':id?' removed together with preceding slash
      // We leave placeholder to strip later; mark with sentinel
      return `__OPT_PARAM__${key}__`;
    }
    return encodeSegment(v);
  });

  // Remove optional segments that were not provided (strip '/__OPT_PARAM__key__')
  out = out.replace(/\/__OPT_PARAM__([A-Za-z0-9_]+)__\b/g, "");

  return out.replace(/\/{2,}/g, "/") || "/";
}

//////////////////// Public API ////////////////////

export type RouteName =
  | "root"
  | "login"
  | "logout"
  | "dashboard"
  | "settings"
  | "settings.profile"
  | "settings.security"
  | "project"
  | "project.task"
  | "search"
  | "notfound";

const ROUTE_SPECS = [
  { name: "root",               pattern: "/" },
  { name: "login",              pattern: "/login" },
  { name: "logout",             pattern: "/logout" },
  { name: "dashboard",          pattern: "/dashboard" },
  { name: "settings",           pattern: "/settings" },
  { name: "settings.profile",   pattern: "/settings/profile" },
  { name: "settings.security",  pattern: "/settings/security" },

  // Dynamic
  { name: "project",            pattern: "/project/:projectId" },
  { name: "project.task",       pattern: "/project/:projectId/task/:taskId" },

  // Optional param and query-centric route
  { name: "search",             pattern: "/search/:tab?" },

  // Splat
  { name: "notfound",           pattern: "/*" },
] as const satisfies readonly RouteSpec<any, any>[];

// Compile once, HMR-safe
declare global {
  interface Window {
    __OMNIMIND_ROUTES__?: {
      compiled: readonly Compiled[];
      map: ReadonlyMap<RouteName, Compiled>;
    };
  }
}

function ensureCompiled() {
  if (!window.__OMNIMIND_ROUTES__) {
    const compiled = ROUTE_SPECS.map(s => compilePattern(s.name, s.pattern as Pattern));
    const map = new Map<RouteName, Compiled>();
    compiled.forEach(c => map.set(c.name as RouteName, c));
    window.__OMNIMIND_ROUTES__ = { compiled, map };
  }
  return window.__OMNIMIND_ROUTES__!;
}

const { compiled: COMPILED, map: COMPILED_MAP } = ensureCompiled();

export type ParamsOf<N extends RouteName> =
  N extends "project" ? { projectId: string } :
  N extends "project.task" ? { projectId: string; taskId: string } :
  N extends "search" ? { tab?: string } :
  N extends "notfound" ? { "*"?: string } :
  {} // static routes

export type QueryOf<N extends RouteName> =
  N extends "search" ? { q?: QueryValue; page?: number; sort?: string } :
  undefined;

/** Build path by route name with params & query & hash */
export function buildPath<N extends RouteName>(
  name: N,
  params: ParamsOf<N> = {} as ParamsOf<N>,
  options?: { query?: QueryOf<N>; hash?: string }
): string {
  const c = COMPILED_MAP.get(name);
  if (!c) throw new Error(`Unknown route: ${name}`);
  const base = interpolate(c.pattern, params as Dict<string>);
  const sp = toSearchParams(options?.query as any);
  const qs = sp.toString();
  const hash = options?.hash ? `#${encodeURIComponent(options.hash)}` : "";
  return `${base}${qs ? `?${qs}` : ""}${hash}`;
}

/** Append/override query to any path */
export function withQuery(path: string, query?: Dict<QueryValue>): string {
  if (!query) return path;
  const [p, q, h] = path.match(/^([^?#]*)(\?[^#]*)?(#.*)?$/)!.slice(1);
  const sp = new URLSearchParams(q?.slice(1));
  const extra = toSearchParams(query);
  extra.forEach((v, k) => {
    sp.delete(k);
    sp.append(k, v);
  });
  const qs = sp.toString();
  return `${p}${qs ? `?${qs}` : ""}${h ?? ""}`;
}

/** Attach/replace hash fragment */
export function withHash(path: string, hash?: string): string {
  const [p, q] = path.split("#", 2);
  return hash ? `${p.replace(/#.*$/, "")}#${encodeURIComponent(hash)}` : p;
}

/** Build full URL from a base (origin) and a path */
export function toURL(path: string, base?: string | URL): URL {
  try {
    if (base) return new URL(path, base);
    return new URL(path, window.location?.origin ?? "http://localhost");
  } catch {
    // Fallback for environments without window
    return new URL(path, "http://localhost");
  }
}

/** Result of matching current pathname against registry */
export type Match =
  | { name: RouteName; params: Dict<string>; pattern: Pattern; path: string }
  | null;

/** Match a pathname to the first matching route */
export function matchPath(pathname: string): Match {
  const path = pathname.replace(/\/{2,}/g, "/");
  for (const c of COMPILED) {
    const m = c.regex.exec(path);
    if (!m) continue;

    const params: Dict<string> = {};
    // c.keys may be fewer than groups if optional worked (undefined handled)
    for (let i = 0; i < c.keys.length; i++) {
      const key = c.keys[i];
      const val = m[i + 1]; // group 1..n
      if (val !== undefined) params[key] = decodeURIComponent(val);
    }
    return { name: c.name as RouteName, params, pattern: c.pattern, path };
  }
  return null;
}

/** Build constant helpers for each route (reverse routing sugar) */
type Builder<N extends RouteName> = (params: ParamsOf<N>, opt?: { query?: QueryOf<N>; hash?: string }) => string;

export const PATHS: Readonly<{
  [K in RouteName]: Builder<K>;
}> = Object.freeze({
  root:      (p, o) => buildPath("root", p as ParamsOf<"root">, o as any),
  login:     (p, o) => buildPath("login", p as ParamsOf<"login">, o as any),
  logout:    (p, o) => buildPath("logout", p as ParamsOf<"logout">, o as any),
  dashboard: (p, o) => buildPath("dashboard", p as ParamsOf<"dashboard">, o as any),
  settings:  (p, o) => buildPath("settings", p as ParamsOf<"settings">, o as any),
  "settings.profile":  (p, o) => buildPath("settings.profile", p as any, o as any),
  "settings.security": (p, o) => buildPath("settings.security", p as any, o as any),
  project:   (p, o) => buildPath("project", p as ParamsOf<"project">, o as any),
  "project.task": (p, o) => buildPath("project.task", p as ParamsOf<"project.task">, o as any),
  search:    (p, o) => buildPath("search", p as ParamsOf<"search">, o as any),
  notfound:  (p, o) => buildPath("notfound", p as ParamsOf<"notfound">, o as any),
});

/** Narrow helper to ensure route name correctness at callsite */
export function route<N extends RouteName>(name: N, params: ParamsOf<N>, opt?: { query?: QueryOf<N>; hash?: string }) {
  return buildPath(name, params, opt);
}

//////////////////// Examples (kept as comments) ////////////////////
// const p1 = PATHS.project({ projectId: "abc" });
// const p2 = PATHS["project.task"]({ projectId: "abc", taskId: "t1" }, { query: { view: "details", v: 1 } });
// const m = matchPath("/project/abc/task/t1");
// const u = toURL(PATHS.search({ tab: "all" }, { query: { q: "otel", page: 2 } }));
