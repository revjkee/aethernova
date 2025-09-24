// src/shared/components/ui/Spinner.tsx
import React, { FC } from 'react'

interface SpinnerProps {
  size?: number
  className?: string
  ariaLabel?: string
}

export const Spinner: FC<SpinnerProps> = ({
  size = 24,
  className = '',
  ariaLabel = 'Loading...'
}) => (
  <svg
    role="status"
    aria-label={ariaLabel}
    className={className}
    width={size}
    height={size}
    viewBox="0 0 50 50"
    fill="none"
    xmlns="http://www.w3.org/2000/svg"
  >
    <circle
      cx="25"
      cy="25"
      r="20"
      stroke="currentColor"
      strokeWidth="5"
      strokeLinecap="round"
      strokeDasharray="90 150"
      strokeDashoffset="0"
      fill="none"
      style={{ opacity: 0.25 }}
    />
    <circle
      cx="25"
      cy="25"
      r="20"
      stroke="currentColor"
      strokeWidth="5"
      strokeLinecap="round"
      strokeDasharray="90 150"
      strokeDashoffset="120"
      fill="none"
      style={{
        transformOrigin: '50% 50%',
        animation: 'spin 1s linear infinite'
      }}
    />
    <style>
      {`
        @keyframes spin {
          100% {
            stroke-dashoffset: 480;
            transform: rotate(360deg);
          }
        }
      `}
    </style>
  </svg>
)
