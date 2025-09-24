import React from 'react'
import ReactDOM from 'react-dom/client'
import { StrictMode } from 'react'
import App from './src/app/App'
import { AppProviders } from './src/app/providers'

// Стиль может быть подключён через index.css или Tailwind (vite → postcss)
import './src/index.css'

const rootElement = document.getElementById('root')

if (!rootElement) {
  throw new Error('Root element with id="root" not found.')
}

const root = ReactDOM.createRoot(rootElement)

root.render(
  <StrictMode>
    <AppProviders>
      <App />
    </AppProviders>
  </StrictMode>
)
