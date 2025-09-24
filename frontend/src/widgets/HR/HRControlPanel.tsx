import React, { useEffect, useState } from 'react'

type ControlsState = {
  hiringOpen: boolean
  diversityMode: 'balanced' | 'aggressive' | 'conservative'
}

export default HRControlPanel


async function fetchWithRetries(url: string, attempts = 3, signal?: AbortSignal) {
  let lastErr: any
  for (let i = 0; i < attempts; i++) {
    try {
      const res = await fetch(url, { signal, headers: { Accept: 'application/json' } })
      if (!res.ok) throw new Error(`status=${res.status}`)
      return await res.json()
    } catch (err) {
      lastErr = err
      if (signal?.aborted) throw err
      await new Promise((r) => setTimeout(r, 120 * Math.pow(2, i)))
    }
  }
  throw lastErr
}

export function HRControlPanel() {
  const [state, setState] = useState<ControlsState | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    const ac = new AbortController()
    setLoading(true)
    fetchWithRetries('/api/hr/controls', 3, ac.signal)
      .then((data) => setState(data || { hiringOpen: true, diversityMode: 'balanced' }))
        .catch((err) => {
          if ((err as any)?.name === 'AbortError') return
          const msg = err instanceof Error ? err.message : String(err)
          setError(msg)
        })
      .finally(() => setLoading(false))

    return () => ac.abort()
  }, [])

  async function toggleHiring() {
    if (!state) return
    setSaving(true)
    try {
      const res = await fetchWithRetries('/api/hr/controls/hiring', 2)
      setState(res)
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      setError(msg)
    } finally {
      setSaving(false)
    }
  }

  async function setDiversityMode(mode: ControlsState['diversityMode']) {
    setSaving(true)
    try {
      const res = await fetchWithRetries('/api/hr/controls/diversity', 2)
      // optimistic local update if API returns success
      setState((s) => (s ? { ...s, diversityMode: mode } : s))
      return res
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      setError(msg)
    } finally {
      setSaving(false)
    }
  }

  if (loading) return <div aria-busy>Загрузка настроек HR…</div>
  if (error) return <div role="alert" style={{ color: 'var(--danger,#b91c1c)' }}>Ошибка: {error}</div>
  if (!state) return <div>Нет данных</div>

  return (
    <section aria-labelledby="hr-control-title" style={{ padding: 12, borderRadius: 8 }}>
      <h3 id="hr-control-title" style={{ margin: '0 0 8px 0' }}>
        HR Control Panel
      </h3>

      <div style={{ display: 'flex', gap: 12, alignItems: 'center', marginBottom: 8 }}>
        <label style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <input
            type="checkbox"
            checked={state.hiringOpen}
            onChange={toggleHiring}
            aria-checked={state.hiringOpen}
            disabled={saving}
          />
          <span>Hiring open</span>
        </label>

        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <span style={{ fontSize: 13, color: 'var(--muted,#6b7280)' }}>Diversity mode:</span>
          <select
            value={state.diversityMode}
            onChange={(e) => setDiversityMode(e.target.value as ControlsState['diversityMode'])}
            disabled={saving}
            aria-label="Select diversity mode"
          >
            <option value="balanced">Balanced</option>
            <option value="aggressive">Aggressive</option>
            <option value="conservative">Conservative</option>
          </select>
        </div>
      </div>

      <div style={{ fontSize: 13, color: 'var(--muted,#6b7280)' }}>
        Последнее состояние: {state.hiringOpen ? 'Hiring' : 'Closed'} • Diversity: {state.diversityMode}
        {saving ? ' • Saving…' : ''}
      </div>
    </section>
  )
}
