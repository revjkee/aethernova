import React, { useEffect, useState } from 'react'

type Diagnostic = {
  id: string
  name: string
  status: 'ok' | 'warn' | 'error'
  metric?: number
  details?: string
}

export default SystemDiagnostic

async function fetchWithRetries(url: string, attempts = 3, signal?: AbortSignal) {
  let lastErr: any
  for (let i = 0; i < attempts; i++) {
    try {
      const res = await fetch(url, { signal })
      if (!res.ok) throw new Error(`status=${res.status}`)
      return await res.json()
    } catch (err) {
      lastErr = err
      if ((err as any)?.name === 'AbortError') throw err
      await new Promise((r) => setTimeout(r, 120 * Math.pow(2, i)))
    }
  }
  throw lastErr
}

export function SystemDiagnostic() {
  const [items, setItems] = useState<Diagnostic[] | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const ac = new AbortController()
    setLoading(true)
    fetchWithRetries('/api/monitoring/diagnostics', 3, ac.signal)
      .then((data) => {
        if (Array.isArray(data)) setItems(data)
        else setItems([])
      })
      .catch((err) => {
        if ((err as any)?.name === 'AbortError') return
        const msg = err instanceof Error ? err.message : String(err)
        setError(msg)
      })
      .finally(() => setLoading(false))

    return () => ac.abort()
  }, [])

  return (
    <section aria-labelledby="sysdiag-title" style={{ padding: 12, borderRadius: 8 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
        <h3 id="sysdiag-title" style={{ margin: 0 }}>System Diagnostic</h3>
        <div style={{ fontSize: 12, color: 'var(--muted,#6b7280)' }}>{loading ? 'Checking…' : 'OK'}</div>
      </div>

      {error && (
        <div role="alert" style={{ color: 'var(--danger,#b91c1c)', marginTop: 8 }}>Ошибка: {error}</div>
      )}

      {!loading && !error && (
        <ul style={{ marginTop: 8, paddingLeft: 14 }}>
          {(items || []).length === 0 && <li style={{ color: 'var(--muted,#6b7280)' }}>No diagnostics available.</li>}
          {(items || []).map((it) => (
            <li key={it.id} style={{ marginBottom: 8 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12 }}>
                <div style={{ fontWeight: 600 }}>{it.name}</div>
                <div style={{ color: it.status === 'ok' ? '#059669' : it.status === 'warn' ? '#b45309' : '#b91c1c' }}>
                  {it.status.toUpperCase()}
                </div>
              </div>
              {typeof it.metric === 'number' && (
                <div style={{ marginTop: 4, fontSize: 13, color: 'var(--muted,#6b7280)' }}>metric: {it.metric}</div>
              )}
              {it.details && (
                <div style={{ marginTop: 6, fontSize: 13, color: 'var(--muted,#6b7280)' }}>{it.details}</div>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}
