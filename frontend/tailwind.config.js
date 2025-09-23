const { fontFamily } = require('tailwindcss/defaultTheme')

/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './index.html',
    './src/**/*.{js,ts,jsx,tsx}',
    './services/**/*.{ts,tsx}',
    './node_modules/@shadcn/ui/**/*.js'
  ],
  darkMode: 'class',
  theme: {
    container: {
      center: true,
      padding: '2rem',
      screens: {
        '2xl': '1440px',
      },
    },
    extend: {
      fontFamily: {
        sans: ['Inter', ...fontFamily.sans],
        mono: ['Fira Code', ...fontFamily.mono]
      },
      colors: {
        primary: {
          DEFAULT: '#3B82F6',  // TeslaAI Blue
          foreground: '#ffffff',
        },
        secondary: {
          DEFAULT: '#64748B',
          foreground: '#ffffff',
        },
        destructive: {
          DEFAULT: '#EF4444',
          foreground: '#ffffff',
        },
        success: '#10B981',
        warning: '#F59E0B',
        background: '#F9FAFB',
        accent: '#6366F1',
        muted: '#E5E7EB',
        border: '#D1D5DB',
      },
      keyframes: {
        'fade-in': {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        'slide-in': {
          '0%': { transform: 'translateY(10px)', opacity: 0 },
          '100%': { transform: 'translateY(0)', opacity: 1 },
        },
      },
      animation: {
        'fade-in': 'fade-in 0.5s ease-in-out',
        'slide-in': 'slide-in 0.6s ease-out',
      },
      boxShadow: {
        'xl-soft': '0 12px 24px rgba(0,0,0,0.08)',
      },
      typography: {
        DEFAULT: {
          css: {
            color: '#1F2937',
            a: { color: '#3B82F6', textDecoration: 'underline' },
            h1: { fontWeight: '700' },
            h2: { fontWeight: '600' },
          }
        }
      }
    },
  },
  plugins: [
    require('@tailwindcss/forms'),
    require('@tailwindcss/typography'),
    require('tailwindcss-animate'),
    require('tailwind-scrollbar'),
  ],
}
