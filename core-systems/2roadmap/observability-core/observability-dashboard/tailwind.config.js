/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        primary: {
          50: '#eff6ff',
          100: '#dbeafe',
          500: '#3b82f6',
          600: '#2563eb',
          700: '#1d4ed8',
          900: '#1e3a8a',
        },
        success: '#10b981',
        warning: '#f59e0b',
        error: '#ef4444',
        dark: {
          800: '#1f2937',
          900: '#111827',
        }
      },
      animation: {
        'pulse-slow': 'pulse 3s infinite',
        'bounce-light': 'bounce 2s infinite',
      }
    },
  },
  plugins: [],
  darkMode: 'class',
}