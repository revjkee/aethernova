import React, { useCallback, useEffect, useRef, useState } from 'react';

export type AgentInfo = {
  id: string;
  name: string;
  status?: 'online' | 'offline' | 'idle' | string;
  avatarUrl?: string;
  description?: string;
};

type Props = {
  agentId?: string;
  baseUrl?: string;
  /** If true, component will fetch agent info from API using agentId. */
  fetchRemote?: boolean;
  onClick?: (agent: AgentInfo | null) => void;
  className?: string;
};

const DEFAULT_AGENT: AgentInfo = {
  id: 'unknown',
  name: 'Unknown Agent',
  status: 'offline',
};

async function fetchWithRetries<T>(url: string, retries = 2, signal?: AbortSignal): Promise<T> {
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

export function UserAgentBanner({ agentId, baseUrl = '', fetchRemote = true, onClick, className = '' }: Props) {
  const [agent, setAgent] = useState<AgentInfo | null>(agentId ? { ...DEFAULT_AGENT, id: agentId, name: 'Loading…' } : null);
  const [loading, setLoading] = useState<boolean>(Boolean(agentId && fetchRemote));
  const [error, setError] = useState<string | null>(null);

  const abortRef = useRef<AbortController | null>(null);
  const mountedRef = useRef(true);

  const loadAgent = useCallback(async () => {
    if (!agentId || !fetchRemote) return;
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    setLoading(true);
    setError(null);
    try {
      const url = `${baseUrl}/api/agents/${encodeURIComponent(agentId)}`;
      const data = await fetchWithRetries<AgentInfo>(url, 2, ac.signal);
      if (!mountedRef.current) return;
      setAgent(data);
      setLoading(false);
    } catch (err: any) {
      if (err?.name === 'AbortError') return;
      setError(String(err?.message ?? err));
      setLoading(false);
    }
  }, [agentId, baseUrl, fetchRemote]);

  useEffect(() => {
    mountedRef.current = true;
    if (agentId && fetchRemote) loadAgent();
    return () => {
      mountedRef.current = false;
      abortRef.current?.abort();
    };
  }, [agentId, fetchRemote, loadAgent]);

  const handleClick = () => {
    if (onClick) onClick(agent);
  };

  const statusColor = (s?: string) => {
    switch (s) {
      case 'online':
        return '#10b981';
      case 'idle':
        return '#f59e0b';
      case 'offline':
      default:
        return '#9ca3af';
    }
  };

  return (
    <div
      role="button"
      tabIndex={0}
      onClick={handleClick}
      onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && handleClick()}
      className={className}
      style={{
        display: 'flex',
        gap: 12,
        alignItems: 'center',
        padding: 10,
        borderRadius: 8,
        background: '#ffffff',
        border: '1px solid #e6e7eb',
        cursor: onClick ? 'pointer' : 'default',
        userSelect: 'none',
      }}
      aria-label={agent ? `Agent ${agent.name}` : 'Agent banner'}
    >
      <div style={{ width: 48, height: 48, borderRadius: 8, overflow: 'hidden', background: '#f3f4f6', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        {agent?.avatarUrl ? (
          // eslint-disable-next-line jsx-a11y/img-redundant-alt
          <img src={agent.avatarUrl} alt={`${agent.name} avatar`} style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
        ) : (
          <svg width="28" height="28" viewBox="0 0 24 24" fill="none" aria-hidden>
            <rect width="24" height="24" rx="4" fill="#e5e7eb" />
            <path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zM4 20c0-2.21 3.58-4 8-4s8 1.79 8 4v1H4v-1z" fill="#9ca3af" />
          </svg>
        )}
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', minWidth: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div style={{ fontSize: 14, fontWeight: 700, color: '#0f172a', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{agent?.name ?? 'Agent'}</div>
          {agent?.status && (
            <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6, marginLeft: 'auto' }}>
              <span style={{ display: 'inline-block', width: 8, height: 8, borderRadius: 99, background: statusColor(agent.status) }} />
              <span style={{ fontSize: 12, color: '#6b7280' }}>{agent.status}</span>
            </div>
          )}
        </div>
        <div style={{ fontSize: 12, color: '#6b7280', marginTop: 4, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{agent?.description ?? (loading ? 'Загрузка…' : '')}</div>
      </div>
    </div>
  );
}

export default UserAgentBanner
