import React, { useCallback, useEffect, useRef, useState } from 'react';

export type ComplianceMetric = {
  id: string;
  label: string;
  score: number; // 0..100
};

export type ComplianceReport = {
  generatedAt?: string;
  metrics: ComplianceMetric[];
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
      const delay = 150 * Math.pow(2, attempt);
      // eslint-disable-next-line no-await-in-loop
      await new Promise((r) => setTimeout(r, delay));
    }
  }
  throw lastErr;
}

function RadarSvg({ metrics }: { metrics: ComplianceMetric[] }) {
  if (!metrics || metrics.length === 0) return <svg width="240" height="240" />;
  const size = 220;
  const cx = size / 2;
  const cy = size / 2;
  const radius = Math.min(cx, cy) - 20;
  const n = metrics.length;
  const step = (Math.PI * 2) / n;

  const points = metrics.map((m, i) => {
    const angle = -Math.PI / 2 + i * step; // start at top
    const r = (m.score / 100) * radius;
    const x = cx + r * Math.cos(angle);
    const y = cy + r * Math.sin(angle);
    return `${x.toFixed(2)},${y.toFixed(2)}`;
  });

  const outer = metrics.map((m, i) => {
    const angle = -Math.PI / 2 + i * step;
    const x = cx + radius * Math.cos(angle);
    const y = cy + radius * Math.sin(angle);
    return `${x.toFixed(2)},${y.toFixed(2)}`;
  });

  const grid = [0.25, 0.5, 0.75, 1].map((f) =>
    metrics
      .map((_, i) => {
        const angle = -Math.PI / 2 + i * step;
        const r = radius * f;
        const x = cx + r * Math.cos(angle);
        const y = cy + r * Math.sin(angle);
        return `${x.toFixed(2)},${y.toFixed(2)}`;
      })
      .join(' ')
  );

  // labels positions (slightly outside outer polygon)
  const labels = metrics.map((m, i) => {
    const angle = -Math.PI / 2 + i * step;
    const x = cx + (radius + 16) * Math.cos(angle);
    const y = cy + (radius + 16) * Math.sin(angle);
    return { x, y, label: m.label };
  });

  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} aria-hidden>
      <defs>
        <linearGradient id="rgrad" x1="0" x2="1">
          <stop offset="0%" stopColor="#0ea5e9" stopOpacity="0.85" />
          <stop offset="100%" stopColor="#34d399" stopOpacity="0.7" />
        </linearGradient>
      </defs>

      {/* grid */}
      <g stroke="#e6edf3" fill="none">
        {grid.map((g, idx) => (
          <polygon key={idx} points={g} />
        ))}
      </g>

      {/* axes */}
      <g stroke="#e6edf3">
        {metrics.map((_, i) => {
          const outerPt = outer[i].split(',').map(Number);
          return <line key={i} x1={cx} y1={cy} x2={outerPt[0]} y2={outerPt[1]} />;
        })}
      </g>

      {/* outer polygon border */}
      <polygon points={outer.join(' ')} fill="none" stroke="#cbd5e1" />

      {/* metric polygon */}
      <polygon points={points.join(' ')} fill="url(#rgrad)" fillOpacity={0.25} stroke="#0ea5e9" strokeWidth={1.5} />

      {/* labels */}
      <g fontSize={11} fill="#0f172a">
        {labels.map((l, i) => (
          <text key={i} x={l.x} y={l.y} textAnchor={Math.abs(l.x - cx) < 6 ? 'middle' : l.x > cx ? 'start' : 'end'} dominantBaseline={l.y > cy ? 'hanging' : 'auto'}>
            {l.label}
          </text>
        ))}
      </g>
    </svg>
  );
}

export function ComplianceRadar({ baseUrl = '', modelId, pollingInterval = 0, retries = DEFAULT_RETRIES }: Props) {
  const apiUrl = `${baseUrl}/api/privacy/compliance${modelId ? `?model=${encodeURIComponent(modelId)}` : ''}`;
  const [report, setReport] = useState<ComplianceReport | null>(null);
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
      const data = await fetchWithRetries<ComplianceReport>(apiUrl, retries, ac.signal);
      if (!mountedRef.current) return;
      // sanitize/normalize
      const metrics = Array.isArray(data?.metrics) ? data.metrics.map((m) => ({ id: m.id, label: m.label, score: Math.max(0, Math.min(100, Number(m.score) || 0) ) })) : [];
      setReport({ generatedAt: data?.generatedAt, metrics });
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
        <h3 style={{ margin: 0, fontSize: 16 }}>Compliance Radar</h3>
        <div style={{ fontSize: 12, color: '#6b7280' }}>{loading ? 'Loading…' : report?.generatedAt ? new Date(report.generatedAt).toLocaleString() : ''}</div>
      </header>

      {error && (
        <div style={{ color: '#b91c1c', marginBottom: 8 }} role="alert">
          Ошибка: {String(error)} <button onClick={() => load()} style={{ marginLeft: 8 }}>Повторить</button>
        </div>
      )}

      {!report || report.metrics.length === 0 ? (
        <div style={{ color: '#6b7280' }}>{loading ? 'Загрузка…' : 'Нет данных для отображения'}</div>
      ) : (
        <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
          <RadarSvg metrics={report.metrics} />
          <div style={{ minWidth: 160 }}>
            <ul style={{ listStyle: 'none', padding: 0, margin: 0, display: 'grid', gap: 8 }}>
              {report.metrics.map((m) => (
                <li key={m.id} style={{ display: 'flex', justifyContent: 'space-between', gap: 8, alignItems: 'center' }}>
                  <div style={{ fontSize: 13 }}>{m.label}</div>
                  <div style={{ fontSize: 13, fontWeight: 700 }}>{Math.round(m.score)}%</div>
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </section>
  );
}

export default ComplianceRadar

