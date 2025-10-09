// frontend/src/pages/PrivacyStatus.tsx
import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";

/**
 * PrivacyStatus — производственная страница статуса приватности.
 * Особенности:
 * - Безопасный фетч с AbortController и экспоненциальным бэкоффом
 * - Авто-реполл (настраиваемый), ручной рефреш, офлайн-индикатор
 * - Скелетоны и понятная UX-сигнализация состояний (idle/loading/error/ok/stale)
 * - Встроенная валидация ответа API и приведение типов
 * - Адаптивная, доступная верстка (ARIA, контраст, клавиатурная навигация)
 * - Нулевые внешние зависимости (только React + Tailwind)
 *
 * Предполагаемый эндпоинт: GET /api/privacy/status
 * Его можно адаптировать через ENV или пропсы при необходимости.
 */

/* =========================================
   Типы домена и безопасный парсер ответа
   ========================================= */

type EncryptionStatus = "ok" | "degraded" | "off";
type RiskLevel = "low" | "medium" | "high";

export interface PrivacyStatusDTO {
  updatedAt: string; // ISO
  trackersBlocked: number;
  dataDeletionRequests: number;
  pendingConsents: number;
  cookieCategories: Array<{ name: string; enabled: boolean }>;
  permissions: {
    camera: "granted" | "denied" | "prompt";
    microphone: "granted" | "denied" | "prompt";
    notifications: "granted" | "denied" | "prompt";
    geolocation: "granted" | "denied" | "prompt";
  };
  encryption: {
    atRest: EncryptionStatus;
    inTransit: EncryptionStatus;
    keyRotationDays: number;
  };
  audit: {
    lastAuditAt: string; // ISO
    issuesFound: number;
    openFindings: number;
  };
  network: {
    vpnActive: boolean;
    torActive: boolean;
    exposedEndpoints: number;
  };
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null;
}

function toBool(v: unknown): boolean {
  return v === true || v === "true" || v === 1;
}

function parseDTO(raw: unknown): PrivacyStatusDTO {
  if (!isRecord(raw)) throw new Error("Invalid payload: not an object");

  const updatedAt = String(raw.updatedAt ?? "");
  const trackersBlocked = Number(raw.trackersBlocked ?? 0);
  const dataDeletionRequests = Number(raw.dataDeletionRequests ?? 0);
  const pendingConsents = Number(raw.pendingConsents ?? 0);

  const cookieCategories = Array.isArray(raw.cookieCategories)
    ? raw.cookieCategories
        .map((c) =>
          isRecord(c)
            ? {
                name: String(c.name ?? "Unknown"),
                enabled: toBool(c.enabled),
              }
            : null,
        )
        .filter(Boolean) as PrivacyStatusDTO["cookieCategories"]
    : [];

  const permissionsRaw = isRecord(raw.permissions) ? raw.permissions : {};
  const asPerm = (v: unknown) =>
    v === "granted" || v === "denied" || v === "prompt" ? v : "prompt" as const;

  const permissions: PrivacyStatusDTO["permissions"] = {
    camera: asPerm(permissionsRaw.camera),
    microphone: asPerm(permissionsRaw.microphone),
    notifications: asPerm(permissionsRaw.notifications),
    geolocation: asPerm(permissionsRaw.geolocation),
  };

  const encryptionRaw = isRecord(raw.encryption) ? raw.encryption : {};
  const asEnc = (v: unknown) =>
    v === "ok" || v === "degraded" || v === "off" ? v : "degraded" as const;

  const encryption: PrivacyStatusDTO["encryption"] = {
    atRest: asEnc(encryptionRaw.atRest),
    inTransit: asEnc(encryptionRaw.inTransit),
    keyRotationDays: Math.max(0, Number(encryptionRaw.keyRotationDays ?? 0)),
  };

  const auditRaw = isRecord(raw.audit) ? raw.audit : {};
  const audit: PrivacyStatusDTO["audit"] = {
    lastAuditAt: String(auditRaw.lastAuditAt ?? ""),
    issuesFound: Math.max(0, Number(auditRaw.issuesFound ?? 0)),
    openFindings: Math.max(0, Number(auditRaw.openFindings ?? 0)),
  };

  const networkRaw = isRecord(raw.network) ? raw.network : {};
  const network: PrivacyStatusDTO["network"] = {
    vpnActive: toBool(networkRaw.vpnActive),
    torActive: toBool(networkRaw.torActive),
    exposedEndpoints: Math.max(0, Number(networkRaw.exposedEndpoints ?? 0)),
  };

  // Базовые инварианты
  if (!updatedAt) throw new Error("Invalid payload: updatedAt missing");

  return {
    updatedAt,
    trackersBlocked,
    dataDeletionRequests,
    pendingConsents,
    cookieCategories,
    permissions,
    encryption,
    audit,
    network,
  };
}

/* =========================================
   Утилиты форматирования и оценки риска
   ========================================= */

function fmtDateTime(iso: string): string {
  try {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return "—";
    return d.toLocaleString(undefined, {
      year: "numeric",
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return "—";
  }
}

function classNames(...xs: Array<string | false | undefined | null>): string {
  return xs.filter(Boolean).join(" ");
}

function encryptionScore(e: PrivacyStatusDTO["encryption"]): number {
  let score = 0;
  score += e.atRest === "ok" ? 40 : e.atRest === "degraded" ? 20 : 0;
  score += e.inTransit === "ok" ? 40 : e.inTransit === "degraded" ? 20 : 0;
  score += Math.max(0, 20 - Math.min(20, e.keyRotationDays)); // чем чаще ротация, тем лучше
  return Math.min(100, Math.max(0, score));
}

function riskFromStatus(dto: PrivacyStatusDTO): RiskLevel {
  const enc = encryptionScore(dto.encryption);
  const openFindings = dto.audit.openFindings;
  const exposed = dto.network.exposedEndpoints;

  if (enc >= 80 && openFindings <= 2 && exposed === 0) return "low";
  if (enc >= 50 && openFindings <= 5 && exposed <= 2) return "medium";
  return "high";
}

/* =========================================
   Хранилище пользовательских настроек
   ========================================= */

type UserPrefs = {
  autoRefreshMs: number; // интервал авто-реполла
  showAdvanced: boolean; // показывать расширенные блоки
};

const DEFAULT_PREFS: UserPrefs = { autoRefreshMs: 30_000, showAdvanced: true };

function loadPrefs(): UserPrefs {
  try {
    const raw = localStorage.getItem("privacy:prefs");
    if (!raw) return DEFAULT_PREFS;
    const parsed = JSON.parse(raw);
    const autoRefreshMs = Number(parsed.autoRefreshMs);
    const showAdvanced = Boolean(parsed.showAdvanced);
    if (!Number.isFinite(autoRefreshMs) || autoRefreshMs < 5_000) {
      return { ...DEFAULT_PREFS, showAdvanced };
    }
    return { autoRefreshMs, showAdvanced };
  } catch {
    return DEFAULT_PREFS;
  }
}

function savePrefs(p: UserPrefs) {
  try {
    localStorage.setItem("privacy:prefs", JSON.stringify(p));
  } catch {
    // ignore storage failures (Safari private mode, etc.)
  }
}

/* =========================================
   Безопасный фетчер с бэкоффом и абортом
   ========================================= */

type FetchState =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "ok"; data: PrivacyStatusDTO; stale?: boolean }
  | { kind: "error"; error: string; since?: number };

async function fetchPrivacyStatus(
  signal: AbortSignal,
  url: string,
): Promise<PrivacyStatusDTO> {
  const res = await fetch(url, { method: "GET", signal, headers: { Accept: "application/json" } });
  if (!res.ok) {
    throw new Error(`HTTP ${res.status}`);
  }
  const json = await res.json();
  return parseDTO(json);
}

function usePrivacyStatus(url = "/api/privacy/status", autoRefreshMs?: number) {
  const [state, setState] = useState<FetchState>({ kind: "idle" });
  const [isOffline, setOffline] = useState<boolean>(!navigator.onLine);
  const abortRef = useRef<AbortController | null>(null);
  const timerRef = useRef<number | null>(null);
  const backoffRef = useRef<number>(1000);

  const clearTimer = () => {
    if (timerRef.current) {
      window.clearTimeout(timerRef.current);
      timerRef.current = null;
    }
  };

  const startTimer = useCallback(
    (ms: number) => {
      clearTimer();
      if (ms > 0) {
        timerRef.current = window.setTimeout(() => {
          void load(true);
        }, ms);
      }
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [],
  );

  const load = useCallback(
    async (background = false) => {
      abortRef.current?.abort();
      const controller = new AbortController();
      abortRef.current = controller;

      if (!background) setState((s) => (s.kind === "ok" ? { ...s, stale: true } : { kind: "loading" }));

      try {
        const data = await fetchPrivacyStatus(controller.signal, url);
        backoffRef.current = 1000; // reset backoff on success
        setState({ kind: "ok", data, stale: false });
      } catch (e: unknown) {
        if ((e as any)?.name === "AbortError") return;
        const msg = e instanceof Error ? e.message : "Unknown error";
        setState({ kind: "error", error: msg, since: Date.now() });
        // schedule retry with exponential backoff
        backoffRef.current = Math.min(backoffRef.current * 2, 60_000);
        startTimer(backoffRef.current);
      }
    },
    [startTimer, url],
  );

  useEffect(() => {
    const onOnline = () => {
      setOffline(false);
      // при восстановлении сети сразу пробуем обновить
      void load(false);
    };
    const onOffline = () => setOffline(true);
    window.addEventListener("online", onOnline);
    window.addEventListener("offline", onOffline);
    return () => {
      window.removeEventListener("online", onOnline);
      window.removeEventListener("offline", onOffline);
    };
  }, [load]);

  useEffect(() => {
    void load(false);
    return () => {
      abortRef.current?.abort();
      clearTimer();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [url]);

  // авто-реполл
  useEffect(() => {
    if (!autoRefreshMs || autoRefreshMs <= 0) return;
    clearTimer();
    timerRef.current = window.setTimeout(() => {
      void load(true);
    }, autoRefreshMs);
    return () => clearTimer();
  }, [autoRefreshMs, state.kind, load]);

  const refresh = useCallback(() => void load(false), [load]);

  return { state, isOffline, refresh };
}

/* =========================================
   Примитивы UI (без внешних библиотек)
   ========================================= */

function SectionCard(props: { title: string; children: React.ReactNode; className?: string }) {
  return (
    <section
      className={classNames(
        "rounded-2xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-sm",
        "p-5 md:p-6",
        props.className,
      )}
      aria-label={props.title}
    >
      <h2 className="text-base md:text-lg font-semibold text-zinc-900 dark:text-zinc-100 mb-3">{props.title}</h2>
      {props.children}
    </section>
  );
}

function StatTile(props: { label: string; value: React.ReactNode; hint?: string }) {
  return (
    <div className="flex flex-col gap-1 rounded-xl border border-zinc-200 dark:border-zinc-800 p-4">
      <div className="text-xs uppercase tracking-wide text-zinc-500 dark:text-zinc-400">{props.label}</div>
      <div className="text-2xl font-semibold text-zinc-900 dark:text-zinc-100">{props.value}</div>
      {props.hint && <div className="text-xs text-zinc-500 dark:text-zinc-400">{props.hint}</div>}
    </div>
  );
}

function Badge(props: { tone: "ok" | "warn" | "danger" | "info"; children: React.ReactNode }) {
  const tone = {
    ok: "bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300 border-green-300/50",
    warn: "bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300 border-amber-300/50",
    danger: "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300 border-red-300/50",
    info: "bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300 border-blue-300/50",
  }[props.tone];
  return <span className={classNames("inline-flex items-center px-2 py-0.5 rounded-md text-xs border", tone)}>{props.children}</span>;
}

function SkeletonLine({ className }: { className?: string }) {
  return <div className={classNames("animate-pulse rounded-md bg-zinc-200 dark:bg-zinc-800 h-4", className)} />;
}

function ProgressBar({ value, srLabel }: { value: number; srLabel: string }) {
  const v = Math.max(0, Math.min(100, Math.round(value)));
  return (
    <div className="w-full" role="progressbar" aria-valuenow={v} aria-valuemin={0} aria-valuemax={100} aria-label={srLabel}>
      <div className="h-2 rounded-full bg-zinc-200 dark:bg-zinc-800">
        <div
          className={classNames(
            "h-2 rounded-full transition-all",
            v >= 80 ? "bg-green-500" : v >= 50 ? "bg-amber-500" : "bg-red-500",
          )}
          style={{ width: `${v}%` }}
        />
      </div>
    </div>
  );
}

/* =========================================
   Основная страница
   ========================================= */

export default function PrivacyStatusPage() {
  // Пользовательские настройки
  const [prefs, setPrefs] = useState<UserPrefs>(() => loadPrefs());
  useEffect(() => savePrefs(prefs), [prefs]);

  // Данные
  const { state, isOffline, refresh } = usePrivacyStatus("/api/privacy/status", prefs.autoRefreshMs);

  // Заголовок документа
  useEffect(() => {
    document.title = "Privacy Status";
  }, []);

  const summary = useMemo(() => {
    if (state.kind !== "ok") return null;
    const risk = riskFromStatus(state.data);
    const encScore = encryptionScore(state.data.encryption);
    return { risk, encScore };
  }, [state]);

  const stale = state.kind === "ok" && state.stale;

  return (
    <main className="mx-auto max-w-7xl px-4 py-6 md:py-8">
      <header className="mb-6 md:mb-8 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div className="flex items-center gap-3">
          <h1 className="text-2xl md:text-3xl font-bold text-zinc-900 dark:text-zinc-100">Privacy Status</h1>
          {isOffline && <Badge tone="warn">Offline</Badge>}
          {stale && <Badge tone="info">Updating…</Badge>}
          {state.kind === "error" && <Badge tone="danger">Error</Badge>}
        </div>

        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={refresh}
            className="inline-flex items-center gap-2 rounded-xl border border-zinc-300 dark:border-zinc-700 px-3 py-2 text-sm hover:bg-zinc-50 dark:hover:bg-zinc-800"
            aria-label="Refresh status"
            data-testid="refresh-button"
          >
            <svg width="16" height="16" viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M17.65 6.35A7.95 7.95 0 0 0 12 4a8 8 0 1 0 8 8h-2a6 6 0 1 1-6-6c1.66 0 3.14.67 4.22 1.76L13 11h7V4z"/></svg>
            Refresh
          </button>

          <div className="flex items-center gap-2">
            <label htmlFor="show-adv" className="text-sm text-zinc-600 dark:text-zinc-300 select-none">
              Advanced
            </label>
            <input
              id="show-adv"
              type="checkbox"
              className="h-4 w-4 accent-zinc-900"
              checked={prefs.showAdvanced}
              onChange={(e) => setPrefs((p) => ({ ...p, showAdvanced: e.target.checked }))}
              aria-label="Toggle advanced sections"
            />
          </div>

          <div className="flex items-center gap-2">
            <label htmlFor="interval" className="text-sm text-zinc-600 dark:text-zinc-300 select-none">
              Auto-refresh
            </label>
            <select
              id="interval"
              className="rounded-lg border border-zinc-300 dark:border-zinc-700 bg-transparent px-2 py-1 text-sm"
              value={String(prefs.autoRefreshMs)}
              onChange={(e) => setPrefs((p) => ({ ...p, autoRefreshMs: Number(e.target.value) }))}
              aria-label="Auto refresh interval"
            >
              <option value="0">Off</option>
              <option value="10000">10s</option>
              <option value="30000">30s</option>
              <option value="60000">60s</option>
            </select>
          </div>
        </div>
      </header>

      {/* Состояния: загрузка / ошибка / контент */}
      {state.kind === "loading" && (
        <div className="grid grid-cols-1 md:grid-cols-12 gap-6">
          <div className="md:col-span-8">
            <SectionCard title="Overview">
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
                <SkeletonLine className="h-20" />
                <SkeletonLine className="h-20" />
                <SkeletonLine className="h-20" />
              </div>
              <div className="mt-4"><SkeletonLine className="h-2 w-1/2" /></div>
            </SectionCard>
          </div>
          <div className="md:col-span-4">
            <SectionCard title="Encryption">
              <SkeletonLine className="h-2 w-3/4 mb-2" />
              <SkeletonLine className="h-2 w-2/3 mb-2" />
              <SkeletonLine className="h-2 w-1/2" />
            </SectionCard>
          </div>
          <div className="md:col-span-6">
            <SectionCard title="Permissions">
              <div className="grid grid-cols-2 gap-3">
                {[...Array(4)].map((_, i) => <SkeletonLine key={i} />)}
              </div>
            </SectionCard>
          </div>
          <div className="md:col-span-6">
            <SectionCard title="Cookies">
              <div className="grid grid-cols-2 gap-3">
                {[...Array(4)].map((_, i) => <SkeletonLine key={i} />)}
              </div>
            </SectionCard>
          </div>
        </div>
      )}

      {state.kind === "error" && (
        <SectionCard title="Error">
          <p className="text-sm text-red-600 dark:text-red-400" role="alert">
            Failed to load privacy status: {state.error}. Please try again.
          </p>
        </SectionCard>
      )}

      {state.kind === "ok" && (
        <>
          <div className="grid grid-cols-1 md:grid-cols-12 gap-6">
            {/* Обзор + Риск */}
            <div className="md:col-span-8">
              <SectionCard title="Overview">
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
                  <StatTile
                    label="Trackers blocked"
                    value={state.data.trackersBlocked.toLocaleString()}
                    hint="Cumulative"
                  />
                  <StatTile
                    label="Deletion requests"
                    value={state.data.dataDeletionRequests.toLocaleString()}
                    hint="Data subject rights"
                  />
                  <StatTile
                    label="Pending consents"
                    value={state.data.pendingConsents.toLocaleString()}
                    hint="Awaiting user action"
                  />
                </div>

                <div className="mt-5 flex items-center gap-3">
                  <span className="text-sm text-zinc-600 dark:text-zinc-300">Risk</span>
                  <Badge
                    tone={
                      summary?.risk === "low" ? "ok" : summary?.risk === "medium" ? "warn" : "danger"
                    }
                  >
                    {summary?.risk?.toUpperCase()}
                  </Badge>
                </div>

                <div className="mt-3">
                  <ProgressBar value={summary?.encScore ?? 0} srLabel="Encryption score" />
                </div>

                <div className="mt-4 text-xs text-zinc-500 dark:text-zinc-400">
                  Updated: {fmtDateTime(state.data.updatedAt)}
                  {stale && " • stale"}
                </div>
              </SectionCard>
            </div>

            {/* Шифрование */}
            <div className="md:col-span-4">
              <SectionCard title="Encryption">
                <ul className="space-y-2 text-sm">
                  <li className="flex items-center justify-between">
                    <span>At rest</span>
                    <Badge tone={state.data.encryption.atRest === "ok" ? "ok" : state.data.encryption.atRest === "degraded" ? "warn" : "danger"}>
                      {state.data.encryption.atRest.toUpperCase()}
                    </Badge>
                  </li>
                  <li className="flex items-center justify-between">
                    <span>In transit</span>
                    <Badge tone={state.data.encryption.inTransit === "ok" ? "ok" : state.data.encryption.inTransit === "degraded" ? "warn" : "danger"}>
                      {state.data.encryption.inTransit.toUpperCase()}
                    </Badge>
                  </li>
                  <li className="flex items-center justify-between">
                    <span>Key rotation</span>
                    <span className="font-medium">{state.data.encryption.keyRotationDays} days</span>
                  </li>
                </ul>
              </SectionCard>
            </div>

            {/* Разрешения */}
            <div className="md:col-span-6">
              <SectionCard title="Permissions">
                <div className="grid grid-cols-2 gap-3 text-sm">
                  {Object.entries(state.data.permissions).map(([k, v]) => (
                    <div key={k} className="flex items-center justify-between rounded-lg border border-zinc-200 dark:border-zinc-800 p-3">
                      <span className="capitalize">{k}</span>
                      <Badge tone={v === "granted" ? "ok" : v === "prompt" ? "info" : "danger"}>
                        {v.toUpperCase()}
                      </Badge>
                    </div>
                  ))}
                </div>
              </SectionCard>
            </div>

            {/* Куки */}
            <div className="md:col-span-6">
              <SectionCard title="Cookies">
                {state.data.cookieCategories.length === 0 ? (
                  <div className="text-sm text-zinc-500 dark:text-zinc-400">No categories</div>
                ) : (
                  <ul className="grid grid-cols-2 gap-3">
                    {state.data.cookieCategories.map((c) => (
                      <li key={c.name} className="flex items-center justify-between rounded-lg border border-zinc-200 dark:border-zinc-800 p-3">
                        <span className="truncate" title={c.name}>{c.name}</span>
                        <Badge tone={c.enabled ? "ok" : "danger"}>{c.enabled ? "ENABLED" : "DISABLED"}</Badge>
                      </li>
                    ))}
                  </ul>
                )}
              </SectionCard>
            </div>

            {/* Аудит */}
            <div className="md:col-span-6">
              <SectionCard title="Audit">
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-sm">
                  <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 p-3">
                    <div className="text-xs text-zinc-500 dark:text-zinc-400">Last audit</div>
                    <div className="font-medium">{fmtDateTime(state.data.audit.lastAuditAt)}</div>
                  </div>
                  <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 p-3">
                    <div className="text-xs text-zinc-500 dark:text-zinc-400">Issues found</div>
                    <div className="font-medium">{state.data.audit.issuesFound}</div>
                  </div>
                  <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 p-3">
                    <div className="text-xs text-zinc-500 dark:text-zinc-400">Open findings</div>
                    <div className="font-medium">{state.data.audit.openFindings}</div>
                  </div>
                </div>
              </SectionCard>
            </div>

            {/* Сеть */}
            <div className="md:col-span-6">
              <SectionCard title="Network">
                <ul className="space-y-3 text-sm">
                  <li className="flex items-center justify-between rounded-lg border border-zinc-200 dark:border-zinc-800 p-3">
                    <span>VPN</span>
                    <Badge tone={state.data.network.vpnActive ? "ok" : "danger"}>
                      {state.data.network.vpnActive ? "ACTIVE" : "INACTIVE"}
                    </Badge>
                  </li>
                  <li className="flex items-center justify-between rounded-lg border border-zinc-200 dark:border-zinc-800 p-3">
                    <span>Tor</span>
                    <Badge tone={state.data.network.torActive ? "ok" : "danger"}>
                      {state.data.network.torActive ? "ACTIVE" : "INACTIVE"}
                    </Badge>
                  </li>
                  <li className="flex items-center justify-between rounded-lg border border-zinc-200 dark:border-zinc-800 p-3">
                    <span>Exposed endpoints</span>
                    <span className="font-medium">{state.data.network.exposedEndpoints}</span>
                  </li>
                </ul>
              </SectionCard>
            </div>
          </div>
        </>
      )}
    </main>
  );
}
