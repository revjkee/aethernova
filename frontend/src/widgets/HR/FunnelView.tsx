import React, { useCallback, useEffect, useRef, useState } from 'react';

export type FunnelStage = {
  key: string;
  label: string;
  count: number;
};

export type FunnelData = {
  total?: number;
  stages: FunnelStage[];
};

type Props = {
  baseUrl?: string;
  pollingInterval?: number; // ms
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
      // eslint-disable-next-line no-await-in-loop
      await new Promise((r) => setTimeout(r, delay));
    }
  }
  throw lastErr;
}

export default FunnelView


function StageRow({ stage, max }: { stage: FunnelStage; max: number }) {
  const pct = max > 0 ? Math.round((stage.count / max) * 100) : 0;
  const color = pct > 66 ? '#059669' : pct > 33 ? '#f59e0b' : '#ef4444';
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
      <div style={{ flex: 1 }}>
        <div style={{ fontSize: 13, color: '#0f172a' }}>{stage.label}</div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 6 }}>
          <div style={{ flex: 1, height: 12, background: '#f3f4f6', borderRadius: 999, overflow: 'hidden' }}>
            <div style={{ width: `${pct}%`, height: '100%', background: color }} />
          </div>
          <div style={{ minWidth: 64, textAlign: 'right', fontSize: 12, color: '#475569' }}>{stage.count} ({pct}%)</div>
        </div>
      </div>
    </div>
  );
}

export function FunnelView({ baseUrl = '', pollingInterval = 0, retries = DEFAULT_RETRIES }: Props) {
  const [data, setData] = useState<FunnelData | null>(null);
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
      const resp = await fetchWithRetries<FunnelData>(`${baseUrl}/api/hr/funnel`, retries, ac.signal);
      if (!mountedRef.current) return;
      setData(resp);
      setLoading(false);
    } catch (err) {
      if ((err as any)?.name === 'AbortError') return;
      if (!mountedRef.current) return;
      setError(err);
      setLoading(false);
    }
  }, [baseUrl, retries]);

  useEffect(() => {
    mountedRef.current = true;
    load();
    if (pollingInterval && pollingInterval > 0) {
      timerRef.current = window.setInterval(() => {
        load();
      }, pollingInterval);
    }
    return () => {
      mountedRef.current = false;
      abortRef.current?.abort();
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [load, pollingInterval]);

  const total = data?.total ?? data?.stages?.reduce((s, it) => s + (it.count || 0), 0) ?? 0;

  return (
    <section style={{ padding: 12, borderRadius: 8, border: '1px solid #e5e7eb', background: '#fff' }} aria-live="polite">
      <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 12 }}>
        <h3 style={{ margin: 0, fontSize: 16 }}>Hiring Funnel</h3>
        <div style={{ fontSize: 12, color: '#6b7280' }}>{loading ? 'Loading…' : error ? 'Ошибка' : `Всего: ${total}`}</div>
      </header>

      {error && (
        <div style={{ color: '#b91c1c', marginBottom: 8 }}>
          Не удалось получить данные: {String(error?.message ?? error)}
          <button onClick={() => load()} style={{ marginLeft: 12 }}>
            Повторить
          </button>
        </div>
      )}

      {!data || data.stages.length === 0 ? (
        <div style={{ color: '#6b7280' }}>{loading ? 'Загрузка…' : 'Нет данных'}</div>
      ) : (
        <div style={{ display: 'grid', gap: 10 }}>
          {data.stages.map((s) => (
            <StageRow key={s.key} stage={s} max={total} />
          ))}
        </div>
      )}
    </section>
  );
}
