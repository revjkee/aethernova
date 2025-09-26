export const APP_NAME = 'Aethernova'

export const API_BASE = (import.meta as any)?.env?.VITE_API_BASE || ''

export const REPO_URL = (import.meta as any)?.env?.VITE_REPO_URL || 'https://github.com/revjkee/aethernova'

export const VERSION = (import.meta as any)?.env?.VITE_APP_VERSION || ''

export function api(path: string) {
  if (!API_BASE) return path
  // ensure leading slash
  const p = path.startsWith('/') ? path : `/${path}`
  return `${API_BASE}${p}`
}

export const DEFAULTS = {
  pageSize: 20,
}

export function getAppVersion() {
  return VERSION
}
