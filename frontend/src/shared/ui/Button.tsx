import React from 'react'

type Variant = 'primary' | 'secondary' | 'ghost'
type Size = 'sm' | 'md' | 'lg'

type Props = React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: Variant
  size?: Size
}

const baseStyles: Record<Variant, React.CSSProperties> = {
  primary: {
    background: 'var(--brand, #0f172a)',
    color: 'white',
    border: 'none',
  },
  secondary: {
    background: 'white',
    color: 'var(--brand, #0f172a)',
    border: '1px solid rgba(15,23,42,0.08)',
  },
  ghost: {
    background: 'transparent',
    color: 'var(--brand, #0f172a)',
    border: 'none',
  },
}

const sizeStyles: Record<Size, React.CSSProperties> = {
  sm: { padding: '6px 10px', fontSize: 13 },
  md: { padding: '8px 12px', fontSize: 14 },
  lg: { padding: '10px 16px', fontSize: 15 },
}

export function Button({ variant = 'primary', size = 'md', style, disabled, ...rest }: Props) {
  const vs = baseStyles[variant]
  const ss = sizeStyles[size]
  const merged: React.CSSProperties = {
    borderRadius: 8,
    cursor: disabled ? 'not-allowed' : 'pointer',
    opacity: disabled ? 0.6 : 1,
    transition: 'transform 120ms ease, box-shadow 120ms ease',
    display: 'inline-flex',
    alignItems: 'center',
    gap: 8,
    ...vs,
    ...ss,
    ...style,
  }

  return <button {...rest} disabled={disabled} style={merged} />
}
export default Button
