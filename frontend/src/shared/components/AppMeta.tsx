import React from 'react'
import { APP_NAME, VERSION } from '../utils/constants'

export function AppMeta({ title, description }: { title?: string; description?: string }) {
  const fullTitle = title ? `${title} — ${APP_NAME}` : APP_NAME
  const desc = description || 'Aethernova — NeuroCity: AI, Web3 and the Metaverse platform.'

  // This component writes basic meta tags; in SSR you'd use head manager.
  // For SPA we update document.title and set a few meta tags when mounted.
  React.useEffect(() => {
    document.title = fullTitle
    const setMeta = (name: string, content: string) => {
      let el = document.querySelector(`meta[name="${name}"]`) as HTMLMetaElement | null
      if (!el) {
        el = document.createElement('meta')
        el.setAttribute('name', name)
        document.head.appendChild(el)
      }
      el.content = content
    }
    setMeta('description', desc)
    setMeta('theme-color', '#0f172a')
    setMeta('aethernova:version', VERSION || '')

    return () => {
      // noop cleanup; keep tags
    }
  }, [fullTitle, desc])

  return null
}

export default AppMeta
