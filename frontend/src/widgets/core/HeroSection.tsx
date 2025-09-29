import React from 'react';

type Props = {
  title?: React.ReactNode;
  subtitle?: React.ReactNode;
  ctaText?: string;
  ctaHref?: string;
  backgroundUrl?: string;
  children?: React.ReactNode;
  className?: string;
};

/**
 * Production-ready HeroSection:
 * - accessible landmarks/heading structure
 * - supports background image or plain color
 * - optional CTA button
 * - lightweight inline styles so no external deps required
 */
export function HeroSection({
  title,
  subtitle,
  ctaText,
  ctaHref,
  backgroundUrl,
  children,
  className = '',
}: Props) {
  const bgStyle: React.CSSProperties = backgroundUrl
    ? {
        backgroundImage: `url(${backgroundUrl})`,
        backgroundSize: 'cover',
        backgroundPosition: 'center',
      }
    : { background: 'linear-gradient(90deg,#ffffff,#f8fafc)' };

  return (
    <section
      aria-label="Hero"
      className={className}
      style={{
        padding: '48px 24px',
        borderRadius: 8,
        color: '#0f172a',
        ...bgStyle,
      }}
    >
      <div style={{ maxWidth: 1100, margin: '0 auto', display: 'flex', gap: 24, alignItems: 'center', flexWrap: 'wrap' }}>
        <div style={{ flex: 1, minWidth: 260 }}>
          {title && (
            <h1 style={{ margin: 0, fontSize: 'clamp(20px, 4vw, 36px)', lineHeight: 1.05 }}>{title}</h1>
          )}
          {subtitle && (
            <p style={{ marginTop: 12, marginBottom: 18, color: '#475569', fontSize: 16 }}>{subtitle}</p>
          )}

          {ctaText && (
            <p style={{ marginTop: 8 }}>
              <a
                href={ctaHref ?? '#'}
                role="button"
                aria-label={ctaText}
                style={{
                  display: 'inline-block',
                  padding: '10px 16px',
                  background: '#0ea5e9',
                  color: '#fff',
                  borderRadius: 8,
                  textDecoration: 'none',
                  fontWeight: 600,
                }}
              >
                {ctaText}
              </a>
            </p>
          )}

          {children}
        </div>

        <div style={{ width: 320, minWidth: 180, display: 'flex', justifyContent: 'center' }}>
          {/* Placeholder visual - keep simple SVG so no external libs required */}
          <svg width="240" height="160" viewBox="0 0 240 160" aria-hidden="true">
            <rect x="0" y="0" width="240" height="160" rx="8" fill="#eef2ff" />
            <g fill="#c7d2fe">
              <rect x="20" y="30" width="60" height="20" rx="4" />
              <rect x="20" y="60" width="200" height="16" rx="4" />
              <rect x="20" y="88" width="160" height="16" rx="4" />
            </g>
          </svg>
        </div>
      </div>
    </section>
  );
}

export default HeroSection
