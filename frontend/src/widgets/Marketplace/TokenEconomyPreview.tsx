import React, { useCallback, useEffect, useRef, useState } from 'react';

export type TokenMetric = {
  id: string;
  label: string;
  value: number;
  history?: { ts: string; value: number }[];
};

export type TokenEconomyData = {
  marketCap?: number;
  circulatingSupply?: number;
  price?: number;
  metrics: TokenMetric[];
  generatedAt?: string;
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
      const delay = 150 * Math.pow(2, attempt);
      // eslint-disable-next-line no-await-in-loop
      await new Promise((r) => setTimeout(r, delay));
    }
  }
  throw lastErr;
}

function TinySpark({ points, color = '#0ea5e9' }: { points?: { ts: string; value: number }[]; color?: string }) {
  if (!points || points.length === 0) return <svg width="120" height="32" />;
  const vals = points.map((p) => p.value);
  const max = Math.max(...vals);
  const min = Math.min(...vals);
  const range = Math.max(1, max - min);
  const w = 120;
  const h = 32;
  const step = w / Math.max(1, points.length - 1);
  const path = points
    .map((p, i) => {
      const x = i * step;
      const y = h - ((p.value - min) / range) * h;
      return `${i === 0 ? 'M' : 'L'} ${x.toFixed(2)} ${y.toFixed(2)}`;
    })
    .join(' ');
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} aria-hidden>
      <path d={path} fill="none" stroke={color} strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function TokenEconomyPreview({ baseUrl = '', pollingInterval = 0, retries = DEFAULT_RETRIES }: Props) {
  const apiUrl = `${baseUrl}/api/marketplace/token-economy`;
  const [data, setData] = useState<TokenEconomyData | null>(null);
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
      const json = await fetchWithRetries<TokenEconomyData>(apiUrl, retries, ac.signal);
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

  const marketCap = data?.marketCap ?? null;
  const price = data?.price ?? null;
  const supply = data?.circulatingSupply ?? null;

  return (
    <section style={{ padding: 12, borderRadius: 8, border: '1px solid #e5e7eb', background: '#fff' }} aria-live="polite">
      <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 12 }}>
        <h3 style={{ margin: 0, fontSize: 16 }}>Token Economy</h3>
        <div style={{ fontSize: 12, color: '#6b7280' }}>{loading ? 'Загрузка…' : data?.generatedAt ? new Date(data.generatedAt).toLocaleString() : ''}</div>
      </header>

      {error && (
        <div style={{ color: '#b91c1c', marginBottom: 8 }} role="alert">
          Ошибка: {String(error)} <button onClick={() => load()} style={{ marginLeft: 8 }}>Повторить</button>
        </div>
      )}

      <div style={{ display: 'grid', gap: 12 }}>
        <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 12, color: '#6b7280' }}>Market cap</div>
            <div style={{ fontSize: 16, fontWeight: 700 }}>{marketCap !== null ? `${marketCap.toLocaleString()} USD` : '—'}</div>
          </div>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 12, color: '#6b7280' }}>Price</div>
            <div style={{ fontSize: 16, fontWeight: 700 }}>{price !== null ? `${price} USD` : '—'}</div>
          </div>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 12, color: '#6b7280' }}>Circulating supply</div>
            <div style={{ fontSize: 16, fontWeight: 700 }}>{supply !== null ? supply.toLocaleString() : '—'}</div>
          </div>
        </div>

        <div>
          <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 8 }}>Metrics</div>
          <div style={{ display: 'grid', gap: 10 }}>
            {data?.metrics?.length ? (
              data.metrics.map((m) => (
                <div key={m.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12 }}>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: 13 }}>{m.label}</div>
                    <div style={{ fontSize: 12, color: '#6b7280' }}>{m.value}</div>
                  </div>
                  <div style={{ width: 140 }}>
                    <TinySpark points={m.history} />
                  </div>
                </div>
              ))
            ) : (
              <div style={{ color: '#6b7280' }}>{loading ? 'Загрузка…' : 'Нет метрик'}</div>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}

export default TokenEconomyPreview
