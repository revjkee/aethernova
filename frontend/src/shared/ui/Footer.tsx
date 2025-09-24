import React from 'react'

export type FooterLink = {
  href: string
  label: string
  external?: boolean
}

export type FooterProps = {
  companyName?: string
  links?: FooterLink[]
  year?: number
}

const defaultLinks: FooterLink[] = [
  { href: '/docs', label: 'Docs' },
  { href: '/about', label: 'About' },
  { href: 'https://github.com/revjkee/aethernova', label: 'GitHub', external: true },
]

export const Footer: React.FC<FooterProps> = ({ companyName = 'Aethernova', links = defaultLinks, year = new Date().getFullYear() }) => {
  const version = (import.meta as any)?.env?.VITE_APP_VERSION || ''

  return (
    <footer
      role="contentinfo"
      aria-label="Site footer"
      style={{
        borderTop: '1px solid rgba(0,0,0,0.06)',
        padding: '12px 16px',
        fontSize: 13,
        color: 'var(--muted, #6b7280)',
        background: 'var(--footer-bg, transparent)',
        display: 'flex',
        gap: 12,
        alignItems: 'center',
        justifyContent: 'space-between',
      }}
    >
      <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
        <div style={{ fontWeight: 700, color: 'var(--brand, #0f172a)' }}>{companyName}</div>
        <div aria-hidden style={{ opacity: 0.6 }}>— NeuroCity</div>
      </div>

      <nav aria-label="Footer links" style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
        {links.map((l) => (
          <a
            key={l.href + l.label}
            href={l.href}
            rel={l.external ? 'noopener noreferrer' : undefined}
            target={l.external ? '_blank' : undefined}
            style={{ color: 'inherit', textDecoration: 'none', opacity: 0.95 }}
          >
            {l.label}
          </a>
        ))}
      </nav>

      <div style={{ display: 'flex', gap: 12, alignItems: 'center', color: 'var(--muted, #6b7280)' }}>
        <span aria-hidden>© {year}</span>
        {version ? <span style={{ opacity: 0.8 }}>v{version}</span> : null}
      </div>
    </footer>
  )
}

export default Footer

