// Расширяем глобальные типы и добавляем общие интерфейсы

// Расширение глобального пространства имён (если нужно)
declare global {
  interface Window {
    // Пример: глобальный объект для телеграм WebApp
    Telegram?: any
  }
}

// Общие типы, используемые в проекте
export interface User {
  id: number
  username?: string
  firstName: string
  lastName?: string
  isAdmin?: boolean
}

export interface ApiResponse<T> {
  success: boolean
  data?: T
  error?: string
}

export interface PaginationParams {
  page: number
  limit: number
}

// Другие глобальные типы и утилиты
export type Nullable<T> = T | null
