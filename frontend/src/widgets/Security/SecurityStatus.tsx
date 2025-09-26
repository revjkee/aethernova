import React, { useCallback, useEffect, useRef, useState } from 'react';

export type SecurityStatusData = {
  id?: string;
  overall?: 'ok' | 'degraded' | 'down' | string;
  incidents?: { id: string; title: string; severity?: string; ts?: string }[];
  lastChecked?: string;
};

type Props = {
  baseUrl?: string;
  pollingInterval?: number; // ms, 0 disables
  retries?: number;
};

const DEFAULT_RETRIES = 2;

async function fetchWithRetries<T>(url: string, retries = DEFAULT_RETRIES, signal?: AbortSignal): Promise<T> {
  let attempt = 0;
  let lastErr: any = null;
  while (attempt <= retries) {
    try {
      const res = await fetch(url, { signal });
      if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText}`);
      const json = (await res.json()) as T;
      return json;
    } catch (err: any) {
      if (err?.name === 'AbortError') throw err;
      lastErr = err;
      attempt += 1;
      const delay = 150 * Math.pow(2, attempt);
      // eslint-disable-next-line no-await-in-loop
      await new Promise((r) => setTimeout(r, delay));
    }
  }
  throw lastErr;
}

export function SecurityStatus({ baseUrl = '', pollingInterval = 0, retries = DEFAULT_RETRIES }: Props) {
  // Default to versioned API for stability; baseUrl can be used to override
  const apiUrl = `${baseUrl}/api/v1/security/status`;
  const [data, setData] = useState<SecurityStatusData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<any>(null);

  const abortRef = useRef<AbortController | null>(null);
  const mountedRef = useRef(true);
  const timerRef = useRef<number | null>(null);

  const load = useCallback(async () => {
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    setLoading(true);
    setError(null);
    try {
      const json = await fetchWithRetries<SecurityStatusData>(apiUrl, retries, ac.signal);
      if (!mountedRef.current) return;
      setData(json);
      setLoading(false);
    } catch (err: any) {
      if (err?.name === 'AbortError') return;
      if (!mountedRef.current) return;
      setError(err?.message ?? String(err));
      setLoading(false);
    }
  }, [apiUrl, retries]);

  useEffect(() => {
    mountedRef.current = true;
    load();
    if (pollingInterval && pollingInterval > 0) {
      timerRef.current = window.setInterval(() => load(), pollingInterval) as unknown as number;
    }
    return () => {
      mountedRef.current = false;
      abortRef.current?.abort();
      if (timerRef.current) clearInterval(timerRef.current as number);
    };
  }, [load, pollingInterval]);

  const overallColor = (s?: string) => {
    switch (s) {
      case 'ok':
        return '#10b981';
      case 'degraded':
        return '#f59e0b';
      case 'down':
        return '#ef4444';
      default:
        return '#6b7280';
    }
  };

  return (
    <section style={{ padding: 12, borderRadius: 8, border: '1px solid #e5e7eb', background: '#fff' }} aria-live="polite">
      <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
        <h3 style={{ margin: 0, fontSize: 16 }}>Security Status</h3>
        <div style={{ fontSize: 12, color: '#6b7280' }}>
          {loading ? 'Checking…' : data?.lastChecked ? (() => {
            try {
              return new Date(data.lastChecked).toLocaleString();
            } catch (_) {
              return String(data.lastChecked);
            }
          })() : ''}
        </div>
      </header>

      {error && (
        <div style={{ color: '#b91c1c', marginBottom: 8 }} role="alert">
          Ошибка загрузки статуса: {String(error)}
          <button onClick={() => load()} style={{ marginLeft: 12 }}>Повторить</button>
        </div>
      )}

      {!data ? (
        <div style={{ color: '#6b7280' }}>{loading ? 'Проверка…' : 'Нет данных'}</div>
      ) : (
        <div style={{ display: 'grid', gap: 10 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <div style={{ width: 12, height: 12, borderRadius: 99, background: overallColor(data.overall) }} aria-hidden />
            <div style={{ fontSize: 14, fontWeight: 700, color: '#0f172a' }}>{data.overall ?? 'unknown'}</div>
          </div>

          {data.incidents && data.incidents.length > 0 ? (
            <div style={{ display: 'grid', gap: 8 }}>
              {data.incidents.map((it) => (
                <article key={it.id} style={{ padding: 8, borderRadius: 6, background: '#fafafa', border: '1px solid #f3f4f6' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                    <div style={{ fontWeight: 600 }}>{it.title}</div>
                    <div style={{ fontSize: 12, color: '#6b7280' }}>{it.ts ? new Date(it.ts).toLocaleString() : ''}</div>
                  </div>
                  {it.severity && <div style={{ fontSize: 12, color: '#6b7280' }}>Severity: {it.severity}</div>}
                </article>
              ))}
            </div>
          ) : (
            <div style={{ color: '#6b7280' }}>Инцидентов не зафиксировано</div>
          )}
        </div>
      )}
    </section>
  );
}

export default SecurityStatus

// Lazy wrapper to be used where needed (keeps original import semantics)
const LazyInner = React.lazy(() => Promise.resolve({ default: SecurityStatus }))
export const LazySecurityStatus: React.FC<Props & { fallback?: React.ReactNode }> = (props) => (
  <React.Suspense fallback={props.fallback ?? null}>
    <LazyInner {...props} />
  </React.Suspense>
)
