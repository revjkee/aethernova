// src/shared/components/ui/Button.tsx
import { cn } from '@/shared/lib/classNames'
import { ButtonHTMLAttributes, FC } from 'react'

type Variant = 'primary' | 'secondary' | 'outline' | 'ghost'
type Size = 'sm' | 'md' | 'lg'

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant
  size?: Size
  fullWidth?: boolean
}

export const Button: FC<ButtonProps> = ({
  children,
  className,
  variant = 'primary',
  size = 'md',
  fullWidth = false,
  ...props
}) => {
  const base =
    'inline-flex items-center justify-center font-medium rounded-2xl transition-colors focus:outline-none focus:ring-2 focus:ring-offset-2 disabled:opacity-50 disabled:pointer-events-none'

  const variants: Record<Variant, string> = {
    primary: 'bg-black text-white hover:bg-neutral-900',
    secondary: 'bg-white text-black border border-gray-300 hover:bg-gray-100',
    outline: 'border border-black text-black hover:bg-neutral-100',
    ghost: 'bg-transparent text-black hover:bg-neutral-100',
  }

  const sizes: Record<Size, string> = {
    sm: 'h-8 px-3 text-sm',
    md: 'h-10 px-4 text-base',
    lg: 'h-12 px-6 text-lg',
  }

  return (
    <button
      className={cn(
        base,
        variants[variant],
        sizes[size],
        fullWidth && 'w-full',
        className
      )}
      {...props}
    >
      {children}
    </button>
  )
}
