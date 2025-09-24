import React, { useEffect, useState } from 'react'

const STORAGE_KEY = 'aethernova:welcome:dismissed'

export function WelcomeOverlay({
  onProceed,
}: {
  onProceed?: () => void
}) {
  const [visible, setVisible] = useState(false)

  useEffect(() => {
    try {
      const dismissed = localStorage.getItem(STORAGE_KEY)
      if (!dismissed) setVisible(true)
    } catch (e) {
      // if storage is blocked, show anyway
      setVisible(true)
    }
  }, [])

  function dismiss(persist = true) {
    if (persist) {
      try {
        localStorage.setItem(STORAGE_KEY, '1')
      } catch (e) {
        // ignore
      }
    }
    setVisible(false)
    onProceed?.()
  }

  if (!visible) return null

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Welcome to Aethernova"
      style={{
        position: 'fixed',
        inset: 0,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'rgba(2,6,23,0.6)',
        zIndex: 9999,
        padding: 20,
      }}
    >
      <div style={{ background: 'white', borderRadius: 10, maxWidth: 720, width: '100%', padding: 20 }}>
        <h2 style={{ marginTop: 0 }}>Welcome to Aethernova — NeuroCity</h2>
        <p style={{ color: 'var(--muted,#6b7280)' }}>
          Aethernova объединяет ИИ, Web3, приватность и 3D-метавселенную. Эта предварительная сборка содержит множество
          модулей: агенты, мониторинг, токеномика и визуализации. Добро пожаловать в город будущего.
        </p>
        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 16 }}>
          <button
            onClick={() => dismiss(false)}
            style={{ padding: '8px 12px', background: 'transparent', border: '1px solid #e5e7eb', borderRadius: 6 }}
          >
            Close
          </button>
          <button
            onClick={() => dismiss(true)}
            style={{ padding: '8px 12px', background: '#0f172a', color: 'white', borderRadius: 6, border: 'none' }}
          >
            Get started
          </button>
        </div>
      </div>
    </div>
  )
}

export default WelcomeOverlay
