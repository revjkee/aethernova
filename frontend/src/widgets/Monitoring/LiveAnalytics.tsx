import React, { useCallback, useEffect, useRef, useState } from 'react';

export type LiveMetric = {
  id: string;
  label: string;
  value: number;
  ts: string; // ISO
};

export type LiveAnalyticsPayload = {
  metrics: LiveMetric[];
  generatedAt?: string;
};

type Props = {
  baseUrl?: string;
  /** If true, try to connect via Server-Sent Events */
  useSSE?: boolean;
  /** fallback polling interval when SSE is not available (ms). 0 disables polling. */
  pollingInterval?: number;
  retries?: number;
  onError?: (err: any) => void;
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

export default LiveAnalytics


/** Small in-memory aggregator to reduce re-renders */
function mergeMetrics(existing: LiveMetric[], incoming: LiveMetric[]) {
  const map = new Map<string, LiveMetric>();
  for (const m of existing) map.set(m.id, m);
  for (const m of incoming) map.set(m.id, m);
  return Array.from(map.values());
}

export function LiveAnalytics({ baseUrl = '', useSSE = true, pollingInterval = 2000, retries = DEFAULT_RETRIES, onError }: Props) {
  const apiUrl = `${baseUrl}/api/monitoring/live`;
  const [metrics, setMetrics] = useState<LiveMetric[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<any>(null);

  const sseRef = useRef<EventSource | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  const mountedRef = useRef(true);
  const pollTimerRef = useRef<number | null>(null);

  const onData = useCallback((payload: LiveAnalyticsPayload) => {
    if (!payload || !Array.isArray(payload.metrics)) return;
    setMetrics((prev) => mergeMetrics(prev, payload.metrics));
    setLoading(false);
  }, []);

  const connectSSE = useCallback(() => {
    if (!useSSE || typeof window === 'undefined') return false;
    try {
      // Prefer a text/event-stream endpoint
      const url = apiUrl.replace(/^http:/, 'http:').replace(/^https:/, 'https:') + '?stream=1';
      const es = new EventSource(url);
      es.onmessage = (e) => {
        try {
          const data = JSON.parse(e.data) as LiveAnalyticsPayload;
          onData(data);
        } catch (err) {
          // malformed payload
        }
      };
      es.onerror = (ev) => {
        // try to reconnect logic handled by browser; we'll fallback to polling on error
        es.close();
        sseRef.current = null;
        // signal to fallback
        setTimeout(() => {
          if (mountedRef.current && pollingInterval && pollingInterval > 0) {
            startPolling();
          }
        }, 500);
      };
      sseRef.current = es;
      return true;
    } catch (err) {
      return false;
    }
  }, [apiUrl, onData, pollingInterval, useSSE]);

  const startPolling = useCallback(() => {
    // stop existing timer
    if (pollTimerRef.current) {
      clearInterval(pollTimerRef.current);
      pollTimerRef.current = null;
    }
    if (!pollingInterval || pollingInterval <= 0) return;
    // immediate fetch
    void (async () => {
      abortRef.current?.abort();
      const ac = new AbortController();
      abortRef.current = ac;
      try {
        const data = await fetchWithRetries<LiveAnalyticsPayload>(apiUrl, retries, ac.signal);
        if (!mountedRef.current) return;
        onData(data);
      } catch (err) {
        if ((err as any)?.name === 'AbortError') return;
        setError(err);
        onError?.(err);
      }
    })();

    pollTimerRef.current = window.setInterval(async () => {
      abortRef.current?.abort();
      const ac = new AbortController();
      abortRef.current = ac;
      try {
        const data = await fetchWithRetries<LiveAnalyticsPayload>(apiUrl, retries, ac.signal);
        if (!mountedRef.current) return;
        onData(data);
      } catch (err) {
        if ((err as any)?.name === 'AbortError') return;
        setError(err);
        onError?.(err);
      }
    }, pollingInterval) as unknown as number;
  }, [apiUrl, onData, pollingInterval, retries, onError]);

  useEffect(() => {
    mountedRef.current = true;
    setLoading(true);
    setError(null);

    let usedSSE = false;
    if (useSSE) {
      usedSSE = connectSSE();
    }
    if (!usedSSE) {
      startPolling();
    }

    return () => {
      mountedRef.current = false;
      try {
        sseRef.current?.close();
      } catch {}
      abortRef.current?.abort();
      if (pollTimerRef.current) clearInterval(pollTimerRef.current);
    };
  }, [connectSSE, startPolling, useSSE]);

  const reset = useCallback(() => {
    setMetrics([]);
    setError(null);
    setLoading(true);
    // restart connections
    try {
      sseRef.current?.close();
    } catch {}
    sseRef.current = null;
    if (pollTimerRef.current) clearInterval(pollTimerRef.current);
    if (useSSE) {
      if (!connectSSE()) startPolling();
    } else {
      startPolling();
    }
  }, [connectSSE, startPolling, useSSE]);

  // lightweight render: list of metrics with sparklines (small inline svg)
  return (
    <section style={{ padding: 12, borderRadius: 8, border: '1px solid #e5e7eb', background: '#fff' }} aria-live="polite">
      <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
        <h3 style={{ margin: 0, fontSize: 16 }}>Live Analytics</h3>
        <div style={{ fontSize: 12, color: '#6b7280' }}>{loading ? 'Подключение…' : `${metrics.length} метрик`}</div>
      </header>

      {error && (
        <div style={{ color: '#b91c1c', marginBottom: 8 }} role="alert">
          Ошибка потоковой передачи: {String(error?.message ?? error)}
          <button onClick={() => reset()} style={{ marginLeft: 12 }}>
            Переподключить
          </button>
        </div>
      )}

      {!metrics || metrics.length === 0 ? (
        <div style={{ color: '#6b7280' }}>{loading ? 'Подключение…' : 'Нет метрик'}</div>
      ) : (
        <div style={{ display: 'grid', gap: 12 }}>
          {metrics.map((m) => (
            <div key={m.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12 }}>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 13, fontWeight: 700 }}>{m.label}</div>
                <div style={{ fontSize: 12, color: '#6b7280' }}>Последнее: {m.value} — {new Date(m.ts).toLocaleTimeString()}</div>
              </div>
              <div style={{ width: 160 }}>
                {/* simple sparkline: for a single point we just render a dot */}
                <svg width="160" height="30" aria-hidden>
                  <rect width="160" height="30" fill="transparent" />
                  <circle cx="12" cy="15" r="6" fill="#0ea5e9" />
                </svg>
              </div>
            </div>
          ))}
        </div>
      )}

      <div style={{ marginTop: 12, display: 'flex', gap: 8 }}>
        <button onClick={() => reset()} style={{ padding: '8px 12px', background: '#0ea5e9', color: '#fff', borderRadius: 8, border: 'none' }}>Переподключить</button>
      </div>
    </section>
  );
}
