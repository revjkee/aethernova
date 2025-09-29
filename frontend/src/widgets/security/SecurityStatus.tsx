import React, { useEffect } from 'react';
import { useSecurityStatus } from './hooks/useSecurityStatus';

type Props = {
  // legacy/compat prop tests use
  pollIntervalMs?: number;
};

/**
 * SecurityStatus component — thin presentation layer driven by useSecurityStatus hook.
 * Exposes stable data-testid attributes and ARIA so tests can target it.
 */
export function SecurityStatus(props: Props) {
  const { pollIntervalMs } = props;
  const { loading, status, score, issues, lastChecked, refresh, error, polling } = useSecurityStatus();

  // no-op debug removed

  const overallColor = (s?: string) => {
    switch (s) {
      case 'ok':
        return '#10b981';
      case 'degraded':
        return '#f59e0b';
      case 'down':
        return '#ef4444';
      default:
        return '#6b7280';
    }
  };

  useEffect(() => {
    if (!polling) return;
    const intervalMs = typeof pollIntervalMs === 'number' ? pollIntervalMs : 30000;
    const iv = setInterval(() => {
      try {
        refresh();
      } catch {
        // swallow
      }
    }, intervalMs);
    return () => clearInterval(iv);
  }, [polling, refresh, pollIntervalMs]);

  return (
    <section
      role="status"
      aria-label="Security Status"
      aria-live="polite"
      style={{ padding: 12, borderRadius: 8, border: '1px solid #e5e7eb', background: '#fff' }}
    >
      <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
        <h3 style={{ margin: 0, fontSize: 16 }}>Security Status</h3>
        <div style={{ fontSize: 12, color: '#6b7280' }} data-testid="security-last-checked">
          {loading ? 'Checking…' : lastChecked ? (() => {
            try { return `Last checked: ${new Date(lastChecked).toLocaleString()}`; } catch { return String(lastChecked); }
          })() : ''}
        </div>
      </header>

      {(status === 'error' || error) && (
        <div style={{ color: '#b91c1c', marginBottom: 8 }} role="alert">
          Ошибка загрузки статуса: {String(error ?? 'ошибка')}
          <button onClick={() => refresh()} style={{ marginLeft: 12 }}>Повторить</button>
        </div>
      )}

      <div style={{ display: 'grid', gap: 10 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ width: 12, height: 12, borderRadius: 99, background: overallColor(status) }} aria-hidden />
          <div
            data-testid="security-status-badge"
            data-status={status}
            aria-label={status ?? 'unknown'}
            style={{ fontSize: 14, fontWeight: 700, color: '#0f172a' }}
          >
            {status ?? 'unknown'}
          </div>
          <div style={{ marginLeft: 'auto' }}>
            <button
              type="button"
              onClick={() => {
                try {
                  // call refresh but don't await to avoid test hangs with fake timers
                  // (tests mock the hook and control loading state separately)
                  // eslint-disable-next-line @typescript-eslint/no-floating-promises
                  refresh();
                  // debug log for test investigation
                  // console.log('SecurityStatus: refresh called');
                } catch {
                  // ignore
                }
              }}
              disabled={loading}
              aria-label="Refresh"
            >
              Refresh
            </button>
          </div>
        </div>

        <div data-testid="security-score" style={{ fontWeight: 700 }}>{typeof score === 'number' && !Number.isNaN(score) ? String(score) : 'N/A'}</div>

        {issues && issues.length > 0 ? (
          <ul role="list" aria-label="Security Issues" style={{ display: 'grid', gap: 8, paddingLeft: 0, listStyle: 'none' }}>
            {issues.map((it) => (
              <li key={it.id} role="listitem">
                <article style={{ padding: 8, borderRadius: 6, background: '#fafafa', border: '1px solid #f3f4f6' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                    <div style={{ fontWeight: 600 }}>{it.title}</div>
                    <div style={{ fontSize: 12, color: '#6b7280' }}>{(it as any).details ?? ''}</div>
                  </div>
                  {(it as any).severity && <div style={{ fontSize: 12, color: '#6b7280' }}>Severity: {(it as any).severity}</div>}
                </article>
              </li>
            ))}
          </ul>
        ) : (
          <div style={{ color: '#6b7280' }}>Инцидентов не зафиксировано</div>
        )}

        {loading && <div data-testid="security-loading" aria-hidden>loading</div>}
      </div>
    </section>
  );
}

export default SecurityStatus;

// Lazy wrapper to preserve previous import semantics where used
const LazyInner = React.lazy(() => Promise.resolve({ default: SecurityStatus }));
export const LazySecurityStatus: React.FC<Props & { fallback?: React.ReactNode }> = (props) => (
  <React.Suspense fallback={props.fallback ?? null}>
    <LazyInner {...props} />
  </React.Suspense>
);
