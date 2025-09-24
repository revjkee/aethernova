import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'
import tsconfigPaths from 'vite-tsconfig-paths'
import path from 'path'

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => {
  // Загружаем переменные окружения в process.env
  const env = loadEnv(mode, process.cwd())

  return {
    plugins: [
      react(),
      tsconfigPaths() // Использует tsconfig.json для алиасов
    ],
    resolve: {
      alias: {
        // Дополнительная защита: дублируем @, если tsconfigPaths не справится
        '@': path.resolve(__dirname, 'src'),
        '@ui': path.resolve(__dirname, 'src/shared/ui'),
        '@api': path.resolve(__dirname, 'services/apiClient.ts')
      }
    },
    css: {
      preprocessorOptions: {
        scss: {
          additionalData: `@import "@/styles/variables.scss";`
        }
      }
    },
    server: {
      host: true,
      port: 3000,
      strictPort: true,
      open: false,
      proxy: {
        '/api': {
          target: env.VITE_API_BASE || 'http://localhost:8000',
          changeOrigin: true,
          rewrite: path => path.replace(/^\/api/, '')
        }
      }
    },
    build: {
      outDir: 'dist',
      sourcemap: true,
      manifest: true,
      target: 'esnext',
      chunkSizeWarningLimit: 600,
      rollupOptions: {
        output: {
          manualChunks(id) {
            if (id.includes('node_modules')) {
              return id.toString().split('node_modules/')[1].split('/')[0]
            }
          }
        }
      }
    },
    define: {
      __APP_VERSION__: JSON.stringify(process.env.npm_package_version || '0.0.1'),
      __BUILD_DATE__: JSON.stringify(new Date().toISOString()),
      __DEPLOY_ENV__: JSON.stringify(mode)
    },
    preview: {
      port: 4173,
      strictPort: true
    }
  }
})
