import React, { useEffect, useMemo, useState } from 'react'

type RiskCell = {
  x: number
  y: number
  score: number // 0..1
  label?: string
}

type RiskGrid = {
  width: number
  height: number
  cells: RiskCell[]
}

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
      // exponential backoff
      await new Promise((r) => setTimeout(r, 200 * Math.pow(2, i)))
    }
  }
  throw lastErr
}

function scoreToColor(score: number) {
  // green (low) to red (high)
  const r = Math.round(255 * score)
  const g = Math.round(200 * (1 - score))
  return `rgb(${r},${g},40)`
}

export function RiskHeatmap({}: {}) {
  const [grid, setGrid] = useState<RiskGrid | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const ac = new AbortController()
    setLoading(true)
    setError(null)
    fetchWithRetries('/api/security/risk-grid', 3, ac.signal)
      .then((data) => {
        // naive shape validation
        if (data && Array.isArray(data.cells)) {
          setGrid({ width: data.width || 6, height: data.height || 6, cells: data.cells })
        } else {
          // fallback: create small synthetic grid
          const cells: RiskCell[] = []
          for (let y = 0; y < 6; y++) for (let x = 0; x < 6; x++) cells.push({ x, y, score: Math.random() })
          setGrid({ width: 6, height: 6, cells })
        }
      })
      .catch((err) => {
        if (err?.name === 'AbortError') return
        setError(String(err?.message || err))
      })
      .finally(() => setLoading(false))

    return () => ac.abort()
  }, [])

  const svg = useMemo(() => {
    if (!grid) return null
    const w = 300
    const h = 300
    const cellW = Math.floor(w / grid.width)
    const cellH = Math.floor(h / grid.height)

    return (
      <svg
        width={w}
        height={h}
        role="img"
        aria-label="Security risk heatmap"
        style={{ maxWidth: '100%', height: 'auto', display: 'block' }}
      >
        {grid.cells.map((c, i) => {
          const x = c.x * cellW
          const y = c.y * cellH
          const color = scoreToColor(Math.max(0, Math.min(1, c.score)))
          return (
            <g key={i}>
              <rect
                x={x}
                y={y}
                width={cellW}
                height={cellH}
                fill={color}
                stroke="rgba(0,0,0,0.06)"
                strokeWidth={1}
              />
              <title>{c.label ?? `(${c.x},${c.y}) risk ${(c.score * 100).toFixed(0)}%`}</title>
            </g>
          )
        })}
      </svg>
    )
  }, [grid])

  return (
    <section aria-labelledby="risk-heatmap-title" style={{ padding: 12, borderRadius: 8 }}>
      <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between' }}>
        <h3 id="risk-heatmap-title" style={{ margin: 0, fontSize: 16 }}>
          Risk Heatmap
        </h3>
        <div style={{ fontSize: 12, color: 'var(--muted, #6b7280)' }}>{loading ? 'Loading…' : error ? 'Error' : 'Live'}</div>
      </div>

      <div style={{ marginTop: 10, minHeight: 120 }}>
        {loading && <div style={{ color: 'var(--muted, #6b7280)' }}>Загрузка данных...</div>}
        {error && (
          <div role="alert" style={{ color: 'var(--danger, #b91c1c)' }}>
            Ошибка: {error}
          </div>
        )}
        {!loading && !error && svg}
      </div>
    </section>
  )
}

export default RiskHeatmap

