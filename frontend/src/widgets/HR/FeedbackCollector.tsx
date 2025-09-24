import React, { useCallback, useEffect, useRef, useState } from 'react';

export type FeedbackItem = {
  id: string;
  author?: string;
  message: string;
  createdAt?: string;
};

type Props = {
  baseUrl?: string;
  /** auto-refresh interval in ms (0 disables) */
  pollingInterval?: number;
  retries?: number;
};

const DEFAULT_RETRIES = 2;

async function fetchWithRetries<T>(url: string, retries = DEFAULT_RETRIES, signal?: AbortSignal): Promise<T> {
  let attempt = 0;
  let lastErr: any = null;
  while (attempt <= retries) {
    try {
      const res = await fetch(url, { signal, headers: { 'Content-Type': 'application/json' } });
      if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText}`);
      // assume JSON
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

export default FeedbackCollector


export function FeedbackCollector({ baseUrl = '', pollingInterval = 0, retries = DEFAULT_RETRIES }: Props) {
  const apiUrl = `${baseUrl}/api/hr/feedback`;

  const [items, setItems] = useState<FeedbackItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [author, setAuthor] = useState('');
  const [message, setMessage] = useState('');
  const [submitting, setSubmitting] = useState(false);

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
      const data = await fetchWithRetries<FeedbackItem[]>(apiUrl, retries, ac.signal);
      if (!mountedRef.current) return;
      setItems(Array.isArray(data) ? data : []);
      setLoading(false);
    } catch (err: any) {
      if (err?.name === 'AbortError') return;
      if (!mountedRef.current) return;
      setError(String(err.message ?? err));
      setLoading(false);
    }
  }, [apiUrl, retries]);

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

  const validate = useCallback(() => {
    if (!message || message.trim().length < 5) return 'Сообщение должно быть не короче 5 символов';
    if (author && author.length > 100) return 'Имя автора слишком длинное';
    return null;
  }, [author, message]);

  const onSubmit = useCallback(
    async (e?: React.FormEvent) => {
      e?.preventDefault();
      const v = validate();
      if (v) {
        setError(v);
        return;
      }

      setSubmitting(true);
      setError(null);

      // optimistic item
      const temp: FeedbackItem = {
        id: `temp-${Date.now()}`,
        author: author || 'Аноним',
        message: message.trim(),
        createdAt: new Date().toISOString(),
      };
      setItems((s) => [temp, ...s]);

      try {
        const res = await fetchWithRetries<FeedbackItem>(apiUrl, retries, undefined);
        // If server responds with created item, replace temp
        if (res && res.id) {
          setItems((s) => [res, ...s.filter((it) => it.id !== temp.id)]);
        } else {
          // fallback: just keep optimistic and refresh
          await load();
        }
        setAuthor('');
        setMessage('');
      } catch (err: any) {
        // rollback optimistic update
        setItems((s) => s.filter((it) => it.id !== temp.id));
        setError(String(err?.message ?? err) || 'Ошибка при отправке');
      } finally {
        if (mountedRef.current) setSubmitting(false);
      }
    },
    [apiUrl, author, message, validate, load, retries]
  );

  return (
    <section style={{ padding: 12, borderRadius: 8, border: '1px solid #e5e7eb', background: '#fff' }} aria-live="polite">
      <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 12 }}>
        <h3 style={{ margin: 0, fontSize: 16 }}>Сбор отзывов сотрудников</h3>
        <div style={{ fontSize: 12, color: '#6b7280' }}>{loading ? 'Загрузка…' : `${items.length} отзывов`}</div>
      </header>

      {error && (
        <div style={{ color: '#b91c1c', marginBottom: 8 }} role="alert">
          {error}
        </div>
      )}

      <form onSubmit={onSubmit} style={{ marginBottom: 12 }}>
        <div style={{ display: 'flex', gap: 8, marginBottom: 8, alignItems: 'center' }}>
          <label style={{ flex: 1 }}>
            <div style={{ fontSize: 12, color: '#6b7280', marginBottom: 4 }}>Ваше имя (необязательно)</div>
            <input
              value={author}
              onChange={(e) => setAuthor(e.target.value)}
              maxLength={100}
              placeholder="Аноним"
              style={{ width: '100%', padding: '8px 10px', borderRadius: 6, border: '1px solid #e5e7eb' }}
              aria-label="Автор"
            />
          </label>
        </div>

        <label style={{ display: 'block', marginBottom: 8 }}>
          <div style={{ fontSize: 12, color: '#6b7280', marginBottom: 4 }}>Сообщение</div>
          <textarea
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            placeholder="Поделитесь наблюдениями или идеями по улучшению"
            rows={4}
            style={{ width: '100%', padding: '10px', borderRadius: 6, border: '1px solid #e5e7eb' }}
            aria-label="Сообщение"
            required
          />
        </label>

        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <button
            type="submit"
            disabled={submitting}
            style={{ padding: '8px 12px', background: '#0ea5e9', color: '#fff', borderRadius: 8, border: 'none', cursor: 'pointer' }}
          >
            {submitting ? 'Отправка…' : 'Отправить'}
          </button>

          <button
            type="button"
            onClick={() => {
              setAuthor('');
              setMessage('');
              setError(null);
            }}
            style={{ padding: '8px 12px', background: '#f3f4f6', color: '#0f172a', borderRadius: 8, border: '1px solid #e5e7eb' }}
          >
            Очистить
          </button>

          <div style={{ marginLeft: 'auto', fontSize: 12, color: '#6b7280' }}>{items.length > 0 ? `${items.length} в базе` : ''}</div>
        </div>
      </form>

      <div style={{ display: 'grid', gap: 8 }}>
        {items.length === 0 && !loading ? (
          <div style={{ color: '#6b7280' }}>Еще нет отзывов</div>
        ) : (
          items.map((it) => (
            <article key={it.id} style={{ padding: 10, borderRadius: 6, background: '#fafafa', border: '1px solid #f3f4f6' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                <div style={{ fontWeight: 600 }}>{it.author ?? 'Аноним'}</div>
                <div style={{ fontSize: 12, color: '#6b7280' }}>{it.createdAt ? new Date(it.createdAt).toLocaleString() : ''}</div>
              </div>
              <div style={{ whiteSpace: 'pre-wrap', color: '#0f172a' }}>{it.message}</div>
            </article>
          ))
        )}
      </div>
    </section>
  );
}
