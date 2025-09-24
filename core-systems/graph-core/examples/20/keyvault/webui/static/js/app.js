// TeslaAI WebUI Core App v9.1 — Real-time Core + AuthGuard + ThemeBootstrap

import { initAuth } from './auth.js'
import { apiGetUserInfo, apiGetSystemStatus } from './api.js'
import { showAlert, loadTheme, enableDarkMode } from './utils.js'

// DOM Ready bootstrap
document.addEventListener('DOMContentLoaded', async () => {
  try {
    // 1. Инициализируем тему
    loadTheme()
    if (window.matchMedia("(prefers-color-scheme: dark)").matches) {
      enableDarkMode()
    }

    // 2. Проверяем авторизацию
    const user = await initAuth()
    if (!user) {
      showAlert('Вы не авторизованы. Перенаправление...', 'danger')
      setTimeout(() => window.location.href = '/login', 1500)
      return
    }

    // 3. Показываем имя пользователя
    document.getElementById('username').textContent = user.name || 'Unknown'

    // 4. Получаем системный статус
    const status = await apiGetSystemStatus()
    renderSystemStatus(status)

    // 5. Подключаем realtime WebSocket
    initWebSocketChannel()

  } catch (err) {
    console.error('[TeslaAI][app.js] Bootstrap error:', err)
    showAlert('Ошибка инициализации UI', 'danger')
  }
})

// UI рендер статуса
function renderSystemStatus(status) {
  const el = document.getElementById('system-status')
  if (!el || !status) return

  el.innerHTML = `
    <span class="badge ${status.online ? 'bg-success' : 'bg-danger'}">
      ${status.online ? 'Online' : 'Offline'}
    </span>
    &nbsp;
    Версия: <code>${status.version}</code>
  `
}

// WebSocket-канал
function initWebSocketChannel() {
  const socket = new WebSocket(`wss://${window.location.host}/ws/events`)

  socket.onopen = () => {
    console.info('[TeslaAI][WS] Connected')
  }

  socket.onmessage = (event) => {
    const msg = JSON.parse(event.data)
    if (msg.type === 'secret_rotated') {
      showAlert(`Ключ ${msg.key_id} был ротирован`, 'info')
    }
    if (msg.type === 'anomaly_detected') {
      showAlert(`Аномалия: ${msg.message}`, 'danger')
    }
  }

  socket.onerror = (e) => {
    console.warn('[TeslaAI][WS] Error:', e)
  }

  socket.onclose = () => {
    showAlert('WebSocket отключён', 'warning')
  }
}
