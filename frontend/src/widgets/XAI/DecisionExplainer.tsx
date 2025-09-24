import React, { useEffect, useState } from 'react'

type Explanation = {
  id: string
  summary: string
  details?: string
  score?: number
}

export default DecisionExplainer


async function fetchWithRetries(url: string, attempts = 3, signal?: AbortSignal) {
  let lastErr: any
  for (let i = 0; i < attempts; i++) {
    try {
      const res = await fetch(url, { signal })
      if (!res.ok) throw new Error(`status=${res.status}`)
      return await res.json()
    } catch (err) {
      lastErr = err
      if (signal?.aborted) throw err
      await new Promise((r) => setTimeout(r, 150 * Math.pow(2, i)))
    }
  }
  throw lastErr
}

export function DecisionExplainer({
  decisionId,
}: {
  decisionId?: string
}) {
  const [explanations, setExplanations] = useState<Explanation[] | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!decisionId) return
    const ac = new AbortController()
    setLoading(true)
    setError(null)
    fetchWithRetries(`/api/xai/decisions/${decisionId}/explanations`, 3, ac.signal)
      .then((data) => {
        if (Array.isArray(data)) setExplanations(data)
        else if (data && Array.isArray(data.explanations)) setExplanations(data.explanations)
        else setExplanations([])
      })
      .catch((err) => {
        if (err?.name === 'AbortError') return
        setError(String(err?.message || err))
      })
      .finally(() => setLoading(false))

    return () => ac.abort()
  }, [decisionId])

  return (
    <section aria-labelledby="decision-explainer-title" style={{ borderRadius: 8, padding: 12 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
        <h4 id="decision-explainer-title" style={{ margin: 0 }}>
          Decision Explainer
        </h4>
        <div style={{ fontSize: 12, color: 'var(--muted,#6b7280)' }}>{loading ? 'Loading…' : ''}</div>
      </div>

      {error && (
        <div role="alert" style={{ color: 'var(--danger,#b91c1c)', marginTop: 8 }}>
          Ошибка: {error}
        </div>
      )}

      {!decisionId && <div style={{ marginTop: 8, color: 'var(--muted,#6b7280)' }}>No decision selected.</div>}

      {explanations && (
        <ul style={{ marginTop: 8, paddingLeft: 14 }}>
          {explanations.length === 0 && <li style={{ color: 'var(--muted,#6b7280)' }}>No explanations available.</li>}
          {explanations.map((e) => (
            <li key={e.id} style={{ marginBottom: 8 }}>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <strong style={{ fontSize: 14 }}>{e.summary}</strong>
                {typeof e.score === 'number' && (
                  <span style={{ fontSize: 12, color: 'var(--muted,#6b7280)' }}>• {(e.score * 100).toFixed(0)}%</span>
                )}
              </div>
              {e.details && (
                <pre style={{ margin: '6px 0 0 0', whiteSpace: 'pre-wrap', fontSize: 13 }}>{e.details}</pre>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}
