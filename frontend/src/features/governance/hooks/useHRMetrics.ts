import { useState, useEffect, useRef, useCallback } from 'react';

/**
 * HR metrics shape returned by the server. Extend as needed.
 */
export interface HRMetrics {
  employeesCount?: number;
  turnoverRate?: number; // percent
  satisfactionScore?: number; // 0..100
  [key: string]: any;
}

export default useHRMetrics

export type UseHRMetricsOptions = {
  /** Polling interval in ms. If null or 0, polling is disabled. */
  pollingInterval?: number | null;
  /** If false, the hook will not perform any network request. */
  enabled?: boolean;
  /** Number of retries for transient failures. */
  retries?: number;
  /** Base url for API calls (optional). Defaults to empty string so relative paths work). */
  baseUrl?: string;
};

/**
 * Production-ready hook to fetch HR metrics.
 * Features:
 * - Type-safe return type
 * - AbortController to cancel in-flight requests on unmount
 * - Simple exponential backoff retries for transient failures
 * - Optional polling
 */
export function useHRMetrics(options: UseHRMetricsOptions = {}) {
  const { pollingInterval = null, enabled = true, retries = 2, baseUrl = '' } = options;

  const [metrics, setMetrics] = useState<HRMetrics | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<any>(null);

  const abortRef = useRef<AbortController | null>(null);
  const mountedRef = useRef<boolean>(true);

  const fetchMetrics = useCallback(async (attempt = 0): Promise<void> => {
    if (!enabled) return;

    // Cancel previous request
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;

    setLoading(true);
    setError(null);

    try {
      const res = await fetch(`${baseUrl}/api/governance/hr/metrics`, { signal: ac.signal });
      if (!res.ok) throw new Error(`Fetch failed: ${res.status} ${res.statusText}`);
      const data: HRMetrics = await res.json();
      if (!mountedRef.current) return;
      setMetrics(data);
      setLoading(false);
    } catch (err: any) {
      if (err?.name === 'AbortError') {
        // fetch was aborted - do nothing
        return;
      }

      // Retry logic for transient errors
      if (attempt < retries) {
        const delay = 300 * Math.pow(2, attempt); // exponential backoff
        await new Promise((r) => setTimeout(r, delay));
        return fetchMetrics(attempt + 1);
      }

      if (!mountedRef.current) return;
      setError(err);
      setLoading(false);
    }
  }, [baseUrl, enabled, retries]);

  useEffect(() => {
    mountedRef.current = true;

    // initial fetch
    fetchMetrics();

    let timer: number | undefined;
    if (pollingInterval && pollingInterval > 0) {
      timer = window.setInterval(() => {
        fetchMetrics();
      }, pollingInterval);
    }

    return () => {
      mountedRef.current = false;
      abortRef.current?.abort();
      if (timer) clearInterval(timer);
    };
  }, [fetchMetrics, pollingInterval]);

  const refresh = useCallback(() => fetchMetrics(), [fetchMetrics]);

  return { metrics, loading, error, refresh } as const;
}
