import React, { useCallback, useEffect, useRef, useState } from 'react';

export type AuditLogEntry = {
  id: string;
  timestamp: string; // ISO
  actor?: string;
  action: string;
  details?: string;
};

type Props = {
  baseUrl?: string;
  pageSize?: number;
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
      const delay = 200 * Math.pow(2, attempt);
      // small backoff
      // eslint-disable-next-line no-await-in-loop
      await new Promise((r) => setTimeout(r, delay));
    }
  }
  throw lastErr;
}

export function AuditLogTimeline({ baseUrl = '', pageSize = 20, pollingInterval = 0, retries = DEFAULT_RETRIES }: Props) {
  const apiBase = `${baseUrl}/api/monitoring/audit-logs`;

  const [items, setItems] = useState<AuditLogEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<any>(null);
  const [page, setPage] = useState(1);
  const [hasMore, setHasMore] = useState(true);

  const abortRef = useRef<AbortController | null>(null);
  const mountedRef = useRef(true);
  const timerRef = useRef<number | null>(null);

  const loadPage = useCallback(async (pageToLoad = 1, replace = false) => {
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    setLoading(true);
    setError(null);
    try {
      const url = `${apiBase}?page=${pageToLoad}&page_size=${pageSize}`;
      const data = await fetchWithRetries<{ results: AuditLogEntry[]; total?: number }>(url, retries, ac.signal);
      if (!mountedRef.current) return;
      const results = Array.isArray(data.results) ? data.results : [];
      setItems((prev) => (replace ? results : [...prev, ...results]));
      setHasMore(results.length === pageSize);
      setLoading(false);
    } catch (err: any) {
      if (err?.name === 'AbortError') return;
      if (!mountedRef.current) return;
      setError(err?.message ?? String(err));
      setLoading(false);
    }
  }, [apiBase, pageSize, retries]);

  useEffect(() => {
    mountedRef.current = true;
    // initial
    setItems([]);
    setPage(1);
    loadPage(1, true);

    if (pollingInterval && pollingInterval > 0) {
      timerRef.current = window.setInterval(() => {
        // refresh first page and replace
        setPage(1);
        loadPage(1, true);
      }, pollingInterval);
    }

    return () => {
      mountedRef.current = false;
      abortRef.current?.abort();
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [loadPage, pollingInterval]);

  const loadMore = useCallback(() => {
    if (loading || !hasMore) return;
    const next = page + 1;
    setPage(next);
    loadPage(next, false);
  }, [hasMore, loading, loadPage, page]);

  return (
    <section style={{ padding: 12, borderRadius: 8, border: '1px solid #e5e7eb', background: '#fff' }} aria-live="polite">
      <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 12 }}>
        <h3 style={{ margin: 0, fontSize: 16 }}>Audit Log</h3>
        <div style={{ fontSize: 12, color: '#6b7280' }}>{loading ? 'Loading…' : `${items.length} записей`}</div>
      </header>

      {error && (
        <div style={{ color: '#b91c1c', marginBottom: 8 }} role="alert">
          Ошибка загрузки: {String(error)}
          <button onClick={() => loadPage(1, true)} style={{ marginLeft: 12 }}>
            Повторить
          </button>
        </div>
      )}

      <div style={{ display: 'grid', gap: 10 }}>
        {items.length === 0 && !loading ? (
          <div style={{ color: '#6b7280' }}>Нет записей аудита</div>
        ) : (
          items.map((it) => (
            <article key={it.id} style={{ padding: 10, borderRadius: 6, background: '#fafafa', border: '1px solid #f3f4f6' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                <div style={{ fontWeight: 600 }}>{it.actor ?? 'system'}</div>
                <div style={{ fontSize: 12, color: '#6b7280' }}>{new Date(it.timestamp).toLocaleString()}</div>
              </div>
              <div style={{ fontSize: 13, color: '#0f172a', marginBottom: 6 }}>{it.action}</div>
              {it.details && <pre style={{ whiteSpace: 'pre-wrap', margin: 0, color: '#374151' }}>{it.details}</pre>}
            </article>
          ))
        )}
      </div>

      <div style={{ marginTop: 12, display: 'flex', justifyContent: 'center' }}>
        {hasMore ? (
          <button
            onClick={loadMore}
            disabled={loading}
            style={{ padding: '8px 12px', background: '#0ea5e9', color: '#fff', borderRadius: 8, border: 'none' }}
          >
            {loading ? 'Загрузка…' : 'Загрузить ещё'}
          </button>
        ) : (
          <div style={{ fontSize: 12, color: '#6b7280' }}>{items.length > 0 ? 'Загружены все записи' : ''}</div>
        )}
      </div>
    </section>
  );
}

export default AuditLogTimeline

