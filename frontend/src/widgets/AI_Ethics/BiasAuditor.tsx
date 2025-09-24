import React, { useCallback, useEffect, useRef, useState } from 'react';

export type BiasMetric = {
  id: string;
  feature: string;
  group?: string; // e.g. 'female', 'male', 'age:18-25'
  score: number; // 0..1 where >0.5 indicates bias toward group (interpretation domain-specific)
  details?: string;
};

export type BiasReport = {
  modelId?: string;
  generatedAt?: string;
  metrics: BiasMetric[];
};

type Props = {
  baseUrl?: string;
  modelId?: string;
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

export default BiasAuditor


function Bar({ value }: { value: number }) {
  const pct = Math.round(Math.max(0, Math.min(1, value)) * 100);
  const color = value >= 0.5 ? '#ef4444' : '#059669';
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{ width: 160, background: '#f3f4f6', height: 12, borderRadius: 6, overflow: 'hidden' }}>
        <div style={{ width: `${pct}%`, background: color, height: '100%' }} />
      </div>
      <div style={{ minWidth: 40, textAlign: 'right', fontSize: 12 }}>{pct}%</div>
    </div>
  );
}

export function BiasAuditor({ baseUrl = '', modelId, pollingInterval = 0, retries = DEFAULT_RETRIES }: Props) {
  const apiUrl = `${baseUrl}/api/ethics/bias${modelId ? `?model=${encodeURIComponent(modelId)}` : ''}`;

  const [report, setReport] = useState<BiasReport | null>(null);
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
      const data = await fetchWithRetries<BiasReport>(apiUrl, retries, ac.signal);
      if (!mountedRef.current) return;
      setReport(data);
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
      timerRef.current = window.setInterval(() => load(), pollingInterval);
    }
    return () => {
      mountedRef.current = false;
      abortRef.current?.abort();
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [load, pollingInterval]);

  return (
    <section style={{ padding: 12, borderRadius: 8, border: '1px solid #e5e7eb', background: '#fff' }} aria-live="polite">
      <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 12 }}>
        <h3 style={{ margin: 0, fontSize: 16 }}>Bias Auditor</h3>
        <div style={{ fontSize: 12, color: '#6b7280' }}>{loading ? 'Loading…' : report?.generatedAt ? new Date(report.generatedAt).toLocaleString() : ''}</div>
      </header>

      {error && (
        <div style={{ color: '#b91c1c', marginBottom: 8 }} role="alert">
          Ошибка: {String(error)}
          <button onClick={() => load()} style={{ marginLeft: 12 }}>
            Повторить
          </button>
        </div>
      )}

      {!report || report.metrics.length === 0 ? (
        <div style={{ color: '#6b7280' }}>{loading ? 'Загрузка…' : 'Нет отчёта о смещениях'}</div>
      ) : (
        <div style={{ display: 'grid', gap: 12 }}>
          {report.metrics.map((m) => (
            <article key={m.id} style={{ padding: 10, borderRadius: 6, background: '#fafafa', border: '1px solid #f3f4f6' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                <div style={{ fontWeight: 600 }}>{m.feature}{m.group ? ` · ${m.group}` : ''}</div>
                <div style={{ fontSize: 12, color: '#6b7280' }}>{m.details ? '' : ''}</div>
              </div>
              <div style={{ marginBottom: 8 }}>
                <Bar value={m.score} />
              </div>
              {m.details && <pre style={{ margin: 0, whiteSpace: 'pre-wrap', color: '#374151' }}>{m.details}</pre>}
            </article>
          ))}
        </div>
      )}
    </section>
  );
}
