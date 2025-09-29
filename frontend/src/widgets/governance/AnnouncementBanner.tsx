import React, { useCallback, useEffect, useRef, useState } from 'react';

export type Announcement = {
  id: string;
  title: string;
  body?: string;
  severity?: 'info' | 'warning' | 'critical';
  createdAt?: string;
  expiresAt?: string;
};

type Props = {
  baseUrl?: string;
  pollingInterval?: number; // ms, 0 disables
  retries?: number;
  storageKey?: string; // key to store dismissed announcement ids
};

const DEFAULT_RETRIES = 2;
const DEFAULT_STORAGE_KEY = 'aethernova:dismissedAnnouncements';

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

function useLocalDismissed(key: string) {
  const read = useCallback((): string[] => {
    try {
      const raw = localStorage.getItem(key);
      if (!raw) return [];
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }, [key]);

  const [dismissed, setDismissed] = useState<string[]>(() => read());

  const dismiss = useCallback((id: string) => {
    setDismissed((prev) => {
      const next = Array.from(new Set([...prev, id]));
      try {
        localStorage.setItem(key, JSON.stringify(next));
      } catch {}
      return next;
    });
  }, [key]);

  return { dismissed, dismiss, refresh: () => setDismissed(read()) } as const;
}

export function AnnouncementBanner({ baseUrl = '', pollingInterval = 0, retries = DEFAULT_RETRIES, storageKey = DEFAULT_STORAGE_KEY }: Props) {
  const apiUrl = `${baseUrl}/api/governance/announcements`;
  const [announcements, setAnnouncements] = useState<Announcement[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<any>(null);

  const abortRef = useRef<AbortController | null>(null);
  const mountedRef = useRef(true);
  const timerRef = useRef<number | null>(null);

  const { dismissed, dismiss, refresh: refreshDismissed } = useLocalDismissed(storageKey);

  const load = useCallback(async () => {
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    setLoading(true);
    setError(null);
    try {
      const data = await fetchWithRetries<Announcement[]>(apiUrl, retries, ac.signal);
      if (!mountedRef.current) return;
      // sort newest first
      const sorted = Array.isArray(data) ? data.slice().sort((a, b) => (b.createdAt || '').localeCompare(a.createdAt || '')) : [];
      setAnnouncements(sorted);
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

  // pick first non-dismissed, not expired announcement
  const now = Date.now();
  const current = announcements.find((a) => {
    if (dismissed.includes(a.id)) return false;
    if (a.expiresAt) {
      const exp = Date.parse(a.expiresAt);
      if (!Number.isNaN(exp) && exp < now) return false;
    }
    return true;
  }) || null;

  const onDismiss = useCallback(() => {
    if (!current) return;
    dismiss(current.id);
  }, [current, dismiss]);

  if (loading && !current) return null; // don't show while initially loading
  if (!current) return null;

  const bg = current.severity === 'critical' ? '#fee2e2' : current.severity === 'warning' ? '#fffbeb' : '#ecfeff';
  const border = current.severity === 'critical' ? '#fecaca' : current.severity === 'warning' ? '#fde68a' : '#99f6e4';

  return (
    <div role="region" aria-live="polite" aria-label="Announcements" style={{ padding: 12, background: bg, border: `1px solid ${border}`, borderRadius: 8, display: 'flex', gap: 12, alignItems: 'flex-start' }}>
      <div style={{ flex: 1 }}>
        <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
          <div style={{ fontWeight: 700, fontSize: 14 }}>{current.title}</div>
          <div style={{ marginLeft: 'auto', fontSize: 12, color: '#6b7280' }}>{current.createdAt ? new Date(current.createdAt).toLocaleString() : ''}</div>
        </div>
        {current.body && <div style={{ marginTop: 8, color: '#0f172a' }}>{current.body}</div>}
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        <button onClick={onDismiss} aria-label="Dismiss announcement" style={{ background: '#fff', border: '1px solid #e5e7eb', borderRadius: 8, padding: '8px 10px', cursor: 'pointer' }}>
          Закрыть
        </button>
        <button onClick={() => { refreshDismissed(); load(); }} aria-label="Обновить объявления" style={{ background: '#fff', border: '1px solid #e5e7eb', borderRadius: 8, padding: '8px 10px', cursor: 'pointer' }}>
          Обновить
        </button>
      </div>
    </div>
  );
}

export default AnnouncementBanner
