import React, { useEffect, useState } from 'react'

async function fetchCommit(signal?: AbortSignal) {
  try {
    const res = await fetch('/api/ci/commit', { signal })
    if (!res.ok) throw new Error(`status=${res.status}`)
    const json = await res.json()
    return json.commit || json.hash || json
  } catch (err) {
    throw err
  }
}

export default GitCommitHash

function shortHash(hash?: string | null) {
  if (!hash) return null
  return String(hash).slice(0, 8)
}

export function GitCommitHash() {
  const [commit, setCommit] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const ac = new AbortController()
    setLoading(true)
    fetchCommit(ac.signal)
      .then((c) => setCommit(String(c)))
      .catch(() => {
        // fallback to env var exposed at build time
        const envCommit = (import.meta as any)?.env?.VITE_GIT_COMMIT || null
        if (envCommit) setCommit(envCommit)
      })
      .finally(() => setLoading(false))

    return () => ac.abort()
  }, [])

  const short = shortHash(commit)
  const repo = (import.meta as any)?.env?.VITE_REPO_URL || ''
  const commitUrl = repo && short ? `${repo.replace(/\.git$/, '')}/commit/${commit}` : null

  return (
    <div aria-live="polite" style={{ fontSize: 12, color: 'var(--muted,#6b7280)' }}>
      {loading ? 'Checking commit…' : commit ? (
        <span>
          commit: <code style={{ fontFamily: 'monospace' }}>{short}</code>
          {commitUrl ? (
            <a href={commitUrl} target="_blank" rel="noopener noreferrer" style={{ marginLeft: 8 }}>
              view
            </a>
          ) : null}
        </span>
      ) : (
        <span>commit: unknown</span>
      )}
    </div>
  )
}
