import { defineConfig } from 'cypress'

export default defineConfig({
  e2e: {
    baseUrl: 'http://localhost:3000',
    specPattern: 'tests/e2e/**/*.cy.{js,ts,jsx,tsx}',
    supportFile: 'tests/e2e/support/index.ts',
    setupNodeEvents(on, config) {
      // Расширяем обработчики событий, если нужно (например, логирование, CI-метки)
      return config
    },
    video: true,
    screenshotOnRunFailure: true,
    retries: {
      runMode: 2,
      openMode: 0
    },
    defaultCommandTimeout: 8000,
    pageLoadTimeout: 10000,
    requestTimeout: 5000,
    viewportWidth: 1440,
    viewportHeight: 900,
    chromeWebSecurity: false,
    env: {
      login_url: '/login',
      dashboard_url: '/dashboard'
    }
  },
  component: {
    devServer: {
      framework: 'react',
      bundler: 'vite'
    },
    specPattern: 'src/**/*.cy.{js,ts,jsx,tsx}'
  },
  projectId: 'teslaai-hr-e2e',
  experimentalSessionAndOrigin: true,
  videoCompression: 32,
  trashAssetsBeforeRuns: true
})
