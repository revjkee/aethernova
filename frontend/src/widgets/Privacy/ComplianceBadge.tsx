import React, { useEffect, useState } from 'react'

type Compliance = {
  compliant: boolean
  level?: 'full' | 'partial' | 'none'
  details?: string
}

export default ComplianceBadge

async function fetchWithRetries(url: string, attempts = 2, signal?: AbortSignal) {
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

export function ComplianceBadge() {
  const [state, setState] = useState<Compliance | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const ac = new AbortController()
    setLoading(true)
    fetchWithRetries('/api/privacy/compliance', 2, ac.signal)
      .then((data) => setState(data))
      .catch(() => {
        // fallback: assume partial compliance
        setState({ compliant: false, level: 'partial', details: 'No data' })
      })
      .finally(() => setLoading(false))

    return () => ac.abort()
  }, [])

  const color = state?.compliant ? '#059669' : state?.level === 'partial' ? '#b45309' : '#b91c1c'

  return (
    <div aria-live="polite" style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
      <span
        role="status"
        aria-label={state ? (state.compliant ? 'Compliant' : 'Non-compliant') : 'Loading compliance'}
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 8,
          padding: '6px 10px',
          borderRadius: 999,
          background: '#fff',
          boxShadow: '0 1px 2px rgba(0,0,0,0.04)',
          border: '1px solid rgba(0,0,0,0.04)',
          fontSize: 13,
        }}
      >
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" aria-hidden>
          <circle cx="12" cy="12" r="10" fill={color || '#e5e7eb'} />
        </svg>
        <span style={{ color: 'var(--muted,#6b7280)' }}>{loading ? 'Checking privacy…' : state?.level ?? 'Unknown'}</span>
      </span>
      <a href="/privacy" style={{ fontSize: 12, color: 'var(--muted,#6b7280)' }}>Privacy</a>
    </div>
  )
}
