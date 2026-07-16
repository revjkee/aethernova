import { defineConfig, splitVendorChunkPlugin } from 'vite';
import react from '@vitejs/plugin-react';
import tsconfigPaths from 'vite-tsconfig-paths';
import checker from 'vite-plugin-checker';
import svgr from 'vite-plugin-svgr';
import { VitePWA } from 'vite-plugin-pwa';
import compression from 'vite-plugin-compression';
import legacy from '@vitejs/plugin-legacy';
import { visualizer } from 'rollup-plugin-visualizer';
import path from 'path';

/**
 * Production-grade Vite config for Omnimind Dashboard (React + TS + Tailwind)
 *
 * Основные фичи:
 * - Путь alias '@' -> /src (tsconfig paths поддержка)
 * - React fast refresh / SWC/react plugin (plugin-react использует SWC при возможности)
 * - TypeScript + ESLint/TS type checking (vite-plugin-checker)
 * - import React SVG как компонент (svgr)
 * - PWA support (vite-plugin-pwa) — конфиг можно расширить под ваши требования
 * - Сжатие артефактов (gzip и brotli)
 * - Legacy build для старых браузеров (опционально)
 * - Анализ бандла (rollup visualizer)
 * - Распределение чанков (manualChunks и splitVendorChunkPlugin)
 * - Оптимизация зависимостей + совместимость с env переменными VITE_*
 *
 * Перед использованием убедитесь, что установлены все плагины:
 * npm i -D @vitejs/plugin-react vite-tsconfig-paths vite-plugin-checker vite-plugin-svgr vite-plugin-pwa vite-plugin-compression rollup-plugin-visualizer @vitejs/plugin-legacy
 */

const root = path.resolve(__dirname);
const srcDir = path.resolve(root, 'src');

export default defineConfig(({ mode }) => {
  const isProd = mode === 'production';

  return {
    root,
    base: process.env.VITE_BASE_PATH || '/', // измените при необходимости: CDN / subpath
    envPrefix: 'VITE_', // все env переменные должны начинаться с VITE_ для безопасности

    resolve: {
      alias: {
        '@': srcDir,
        // добавьте дополнительные алиасы при необходимости
      },
      extensions: ['.tsx', '.ts', '.js', '.jsx', '.json'],
    },

    plugins: [
      // React plugin (Fast Refresh + SWC jsx transform если доступно)
      react({
        // jsx runtime automatic + development options
        jsxRuntime: 'automatic',
        babel: {
          // при необходимости добавить оптимизации babel
        },
      }),

      // Поддержка путей из tsconfig (удобно для больших проектов)
      tsconfigPaths(),

      // Проверки типов и eslint в dev (отдельный процесс)
      checker({
        typescript: true,
        eslint: {
          lintCommand: 'eslint "./src/**/*.{ts,tsx,js,jsx}"', // подкорректируйте путь
        },
      }),

      // Импорт SVG как React-компонентов: import { ReactComponent as Icon } from './icon.svg'
      svgr(),

      // PWA: service worker, manifest — базовая конфигурация, расширите под свой проект
      VitePWA({
        registerType: 'autoUpdate',
        includeAssets: ['favicon.svg', 'robots.txt', 'apple-touch-icon.png'],
        manifest: {
          name: 'Omnimind Dashboard',
          short_name: 'Omnimind',
          description: 'Omnimind core dashboard',
          theme_color: '#0ea5a4',
          icons: [
            {
              src: '/pwa-192.png',
              sizes: '192x192',
              type: 'image/png',
            },
            {
              src: '/pwa-512.png',
              sizes: '512x512',
              type: 'image/png',
            },
          ],
        },
        workbox: {
          // кеширование: настройте под правила безопасности
          runtimeCaching: [
            {
              urlPattern: /^https:\/\/your-cdn\.example\//,
              handler: 'CacheFirst',
              options: {
                cacheName: 'cdn-cache',
                expiration: {
                  maxEntries: 100,
                  maxAgeSeconds: 60 * 60 * 24 * 30,
                },
              },
            },
          ],
        },
      }),

      // Сжатие выходных артефактов (gzip + brotli)
      compression({ algorithm: 'gzip', ext: '.gz' }),
      compression({ algorithm: 'brotliCompress', ext: '.br' }),

      // Split vendor vendor chunk helper (vite >= 3)
      splitVendorChunkPlugin(),

      // Legacy build (если нужна поддержка IE11 / старых браузеров) — можно отключить
      legacy({
        targets: ['defaults', 'not IE 11'],
      }),

      // Анализ бандла по требованию — генерирует html визуализацию после сборки
      visualizer({
        filename: path.resolve(root, 'build', 'bundle-visualizer.html'),
        open: false,
        gzipSize: true,
        brotliSize: true,
      }),
    ],

    css: {
      // Tailwind/PostCSS: используйте postcss.config.js + tailwind.config.js в корне
      preprocessorOptions: {
        scss: {
          // дополнительные глобальные переменные/миксины
          additionalData: `@import "@/styles/_variables.scss";`,
        },
      },
      modules: {
        // Избегаем конфликтов имен в больших проектах
        scopeBehaviour: 'local',
        generateScopedName: isProd
          ? '[hash:base64:8]'
          : '[name]__[local]__[hash:base64:5]',
      },
      devSourcemap: !isProd,
    },

    server: {
      host: '0.0.0.0',
      port: Number(process.env.VITE_DEV_PORT) || 5173,
      strictPort: false,
      open: false,
      cors: true,
      // Настройка прокси для backend api — корректируйте target под вашу среду
      proxy: {
        '/api': {
          target: process.env.VITE_API_PROXY || 'http://localhost:8000',
          changeOrigin: true,
          secure: false,
          rewrite: (p) => p.replace(/^\/api/, ''),
        },
        '/auth': {
          target: process.env.VITE_AUTH_PROXY || 'http://localhost:9000',
          changeOrigin: true,
          secure: false,
        },
      },
      hmr: {
        protocol: 'ws',
        overlay: true,
      },
    },

    optimizeDeps: {
      // включаем явно крупные либы для ускорения cold-start
      include: ['react', 'react-dom', 'react-router-dom', 'axios'],
      exclude: ['some-large-legacy-lib'],
    },

    build: {
      target: 'es2019',
      outDir: path.resolve(root, 'dist'),
      assetsDir: 'assets',
      sourcemap: isProd ? false : 'inline',
      minify: 'esbuild', // быстро и безопасно; при необходимости switch to 'terser'
      cssCodeSplit: true,
      brotliSize: true,
      chunkSizeWarningLimit: 1200, // kB, поднято для большого SPA
      rollupOptions: {
        output: {
          // Контроль над разбиением чанков — важно для кэширования и long-term caching
          entryFileNames: 'assets/js/[name]-[hash].js',
          chunkFileNames: 'assets/js/[name]-[hash].js',
          assetFileNames: ({ name }) => {
            if (/\.(css)$/.test(String(name))) return 'assets/css/[name]-[hash][extname]';
            if (/\.(png|jpe?g|svg|gif|webp)$/.test(String(name))) return 'assets/img/[name]-[hash][extname]';
            return 'assets/[name]-[hash][extname]';
          },
          manualChunks(id) {
            if (id.includes('node_modules')) {
              // разделение React / UI libs / vendors
              if (id.match(/node_modules\/(react|react-dom|react-router|react-router-dom)/)) {
                return 'vendor-react';
              }
              if (id.match(/node_modules\/(chart.js|recharts|d3|@visx)/)) {
                return 'vendor-charts';
              }
              if (id.match(/node_modules\/(lodash|dayjs|date-fns)/)) {
                return 'vendor-utils';
              }
              return 'vendor';
            }
          },
        },
      },
    },

    preview: {
      host: true,
      port: Number(process.env.VITE_PREVIEW_PORT) || 5173,
      strictPort: false,
    },

    // Define replacements available at build time
    define: {
      __APP_NAME__: JSON.stringify(process.env.VITE_APP_NAME || 'Omnimind Dashboard'),
      'process.env.NODE_ENV': JSON.stringify(process.env.NODE_ENV || (isProd ? 'production' : 'development')),
    },

    // Логирование: уменьшить в prod
    logLevel: isProd ? 'info' : 'info',
  };
});
