import React, { useCallback, useEffect, useRef, useState } from 'react';

type Props = {
  baseUrl?: string;
  pollingInterval?: number; // ms
  onOpenFeedback?: () => void;
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

export function FeedbackBar({ baseUrl = '', pollingInterval = 0, onOpenFeedback, retries = DEFAULT_RETRIES }: Props) {
  const apiUrl = `${baseUrl}/api/hr/feedback/count`;
  const [count, setCount] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const abortRef = useRef<AbortController | null>(null);
  const timerRef = useRef<number | null>(null);
  const mountedRef = useRef(true);

  const load = useCallback(async () => {
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    setLoading(true);
    setError(null);
    try {
      const data = await fetchWithRetries<{ count: number }>(apiUrl, retries, ac.signal);
      if (!mountedRef.current) return;
      setCount(typeof data.count === 'number' ? data.count : 0);
      setLoading(false);
    } catch (err: any) {
      if (err?.name === 'AbortError') return;
      if (!mountedRef.current) return;
      setError(String(err?.message ?? err));
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
    <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
      <div style={{ fontSize: 13, color: '#0f172a' }} aria-live="polite">
        {loading ? 'Загрузка…' : error ? '—' : count !== null ? `${count} отзывов` : '—'}
      </div>
      <button
        onClick={() => onOpenFeedback?.()}
        style={{
          padding: '8px 12px',
          background: '#0ea5e9',
          color: '#fff',
          borderRadius: 8,
          border: 'none',
          cursor: 'pointer',
        }}
        aria-label="Открыть форму отзывов"
      >
        Оставить отзыв
      </button>
    </div>
  );
}

export default FeedbackBar;
