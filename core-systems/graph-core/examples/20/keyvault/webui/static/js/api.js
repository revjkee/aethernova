// TeslaAI API Client v10.0 — Secure REST + Resilient WebSocket + Token Injection

import { getCSRFToken, getAccessToken } from './utils.js'
import { showAlert } from './utils.js'

const BASE_API_URL = '/api/v1'

// Универсальный fetch-клиент
async function apiRequest(method, endpoint, data = null, requiresAuth = true) {
  const headers = {
    'Content-Type': 'application/json',
    'X-CSRF-Token': getCSRFToken(),
  }

  if (requiresAuth) {
    const token = getAccessToken()
    if (!token) throw new Error("Нет токена доступа")
    headers['Authorization'] = `Bearer ${token}`
  }

  const options = {
    method,
    headers,
    body: data ? JSON.stringify(data) : undefined,
  }

  const response = await fetch(`${BASE_API_URL}${endpoint}`, options)
  if (!response.ok) {
    const errorText = await response.text()
    throw new Error(`[API Error ${response.status}] ${errorText}`)
  }

  return await response.json()
}

// Получение информации о пользователе
export async function apiGetUserInfo() {
  return await apiRequest('GET', '/user/info')
}

// Получение статуса системы
export async function apiGetSystemStatus() {
  return await apiRequest('GET', '/system/status', null, false)
}

// Получение списка секретов
export async function apiListSecrets() {
  return await apiRequest('GET', '/secrets')
}

// Создание нового секрета
export async function apiCreateSecret(payload) {
  return await apiRequest('POST', '/secrets', payload)
}

// Удаление секрета
export async function apiDeleteSecret(secretId) {
  return await apiRequest('DELETE', `/secrets/${encodeURIComponent(secretId)}`)
}

// Ротация секрета
export async function apiRotateSecret(secretId, payload) {
  return await apiRequest('POST', `/secrets/${encodeURIComponent(secretId)}/rotate`, payload)
}

// Получение истории аудита
export async function apiGetAuditLog(limit = 100) {
  return await apiRequest('GET', `/audit?limit=${limit}`)
}

// Получение уведомлений через WebSocket
export function openEventWebSocket(onMessage) {
  const ws = new WebSocket(`wss://${window.location.host}/ws/events`)
  
  ws.onmessage = event => {
    try {
      const msg = JSON.parse(event.data)
      onMessage(msg)
    } catch (e) {
      console.warn('[TeslaAI][WS] Invalid message:', e)
    }
  }

  ws.onerror = err => {
    console.error('[TeslaAI][WS] Socket error:', err)
    showAlert('Ошибка WebSocket', 'danger')
  }

  return ws
}
