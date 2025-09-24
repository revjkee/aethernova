import React, { useEffect, useRef, useState, useCallback } from 'react';

export type DiversitySegment = {
  label: string;
  value: number; // absolute count or percentage (server should document which)
};

export type DiversityData = {
  total?: number;
  segments: DiversitySegment[];
};

type Props = {
  /** Optional base url for the API (defaults to relative) */
  baseUrl?: string;
  /** Polling interval in ms. 0 or undefined disables polling */
  pollingInterval?: number;
  /** Number of retries for transient failures */
  retries?: number;
};

const DEFAULT_RETRIES = 2;

function useFetchJson<T>(url: string, opts: { retries?: number; enabled?: boolean } = {}) {
  const { retries = DEFAULT_RETRIES, enabled = true } = opts;
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<any>(null);

  const abortRef = useRef<AbortController | null>(null);

  const fetchOnce = useCallback(async (attempt = 0) => {
    if (!enabled) return;
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;

    setLoading(true);
    setError(null);

    try {
      const res = await fetch(url, { signal: ac.signal });
      if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText}`);
      const json = (await res.json()) as T;
      setData(json);
      setLoading(false);
    } catch (err: any) {
      if (err?.name === 'AbortError') return;
      if (attempt < retries) {
        const delay = 200 * Math.pow(2, attempt);
        await new Promise((r) => setTimeout(r, delay));
        return fetchOnce(attempt + 1);
      }
      setError(err);
      setLoading(false);
    }
  }, [url, retries, enabled]);

  useEffect(() => {
    fetchOnce();
    return () => abortRef.current?.abort();
  }, [fetchOnce]);

  return { data, loading, error, refresh: fetchOnce } as const;
}

export default DiversityTracker

function SimpleBar({ value, max }: { value: number; max: number }) {
  const pct = max > 0 ? Math.round((value / max) * 100) : 0;
  const color = pct > 66 ? '#1f7a1f' : pct > 33 ? '#f59e0b' : '#ef4444';
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{ width: 160, background: '#f3f4f6', height: 14, borderRadius: 6, overflow: 'hidden' }}>
        <div style={{ width: `${pct}%`, background: color, height: '100%' }} />
      </div>
      <div style={{ minWidth: 48, textAlign: 'right', fontSize: 12 }}>{pct}%</div>
    </div>
  );
}

export function DiversityTracker({ baseUrl = '', pollingInterval = 0, retries = DEFAULT_RETRIES }: Props) {
  const apiUrl = `${baseUrl}/api/hr/diversity`;
  const { data, loading, error, refresh } = useFetchJson<DiversityData>(apiUrl, { retries, enabled: true });

  // polling
  const timerRef = useRef<number | null>(null);
  useEffect(() => {
    if (pollingInterval && pollingInterval > 0) {
      timerRef.current = window.setInterval(() => {
        refresh();
      }, pollingInterval);
    }
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [pollingInterval, refresh]);

  const total = data?.total ?? data?.segments?.reduce((s, it) => s + (it.value || 0), 0) ?? 0;

  return (
    <section style={{ padding: 12, borderRadius: 8, border: '1px solid #e5e7eb', background: '#fff' }}>
      <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 12 }}>
        <h3 style={{ margin: 0, fontSize: 16 }}>Diversity Tracker</h3>
        <div style={{ fontSize: 12, color: '#6b7280' }}>{loading ? 'Loading…' : error ? 'Ошибка' : `Всего: ${total}`}</div>
      </header>

      {error && (
        <div style={{ color: '#b91c1c', marginBottom: 8 }}>
          Не удалось загрузить данные: {String(error?.message ?? error)}
          <button onClick={() => refresh()} style={{ marginLeft: 12 }}>
            Повторить
          </button>
        </div>
      )}

      {!data || data.segments.length === 0 ? (
        <div style={{ color: '#6b7280' }}>Нет данных</div>
      ) : (
        <div style={{ display: 'grid', gap: 10 }}>
          {data.segments.map((s) => (
            <div key={s.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ display: 'flex', flexDirection: 'column' }}>
                <div style={{ fontSize: 13 }}>{s.label}</div>
                <div style={{ fontSize: 12, color: '#6b7280' }}>{s.value} 
                  {typeof total === 'number' && total > 0 ? ` (${Math.round((s.value / total) * 100)}%)` : ''}
                </div>
              </div>
              <SimpleBar value={s.value} max={Math.max(1, total)} />
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
