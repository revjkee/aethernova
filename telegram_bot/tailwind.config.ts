// tailwind.config.ts
import type { Config } from 'tailwindcss';

const config: Config = {
  content: [
    './index.html',
    './src/**/*.{ts,tsx}', // все TS и TSX файлы проекта
  ],
  theme: {
    extend: {
      colors: {
        tg: {
          background: 'var(--tg-bg-color)',
          text: 'var(--tg-text-color)',
          hint: 'var(--tg-hint-color)',
          link: 'var(--tg-link-color)',
          button: 'var(--tg-button-color)',
          buttonText: 'var(--tg-button-text-color)',
          secondaryBg: 'var(--tg-secondary-bg-color)',
        },
      },
      borderRadius: {
        xl: '1rem',
        '2xl': '1.5rem',
      },
    },
  },
  plugins: [],
};

export default config;
