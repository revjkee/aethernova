import { useCallback, useState } from 'react';

export type SecurityStatusHook = {
  loading: boolean;
  status: 'unknown' | 'healthy' | 'degraded' | 'critical' | 'error' | 'loading';
  score: number | null;
  issues: Array<{ id: string; title: string; severity: 'low' | 'medium' | 'high'; details?: string }> | null;
  lastChecked: string | null;
  refresh: () => Promise<void> | void;
  error?: string | null;
  polling?: boolean;
};

export function useSecurityStatus(): SecurityStatusHook {
  const [loading] = useState(false);
  const refresh = useCallback(async () => {}, []);
  return {
    loading,
    status: 'unknown',
    score: null,
    issues: null,
    lastChecked: null,
    refresh,
    error: null,
    polling: false,
  };
}

export default useSecurityStatus;
