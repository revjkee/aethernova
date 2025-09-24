import { useState, useEffect } from 'react'

/**
 * useLocalStorage — хук для хранения состояния в localStorage с автоматической синхронизацией
 * @param key — ключ в localStorage
 * @param initialValue — начальное значение
 * @returns [value, setValue] — значение и функция для обновления
 */
export function useLocalStorage<T>(key: string, initialValue: T) {
  const [storedValue, setStoredValue] = useState<T>(() => {
    if (typeof window === 'undefined') return initialValue
    try {
      const item = window.localStorage.getItem(key)
      return item ? (JSON.parse(item) as T) : initialValue
    } catch (error) {
      console.warn(`useLocalStorage: не удалось прочитать ключ "${key}" из localStorage`, error)
      return initialValue
    }
  })

  const setValue = (value: T | ((val: T) => T)) => {
    try {
      const valueToStore = value instanceof Function ? value(storedValue) : value
      setStoredValue(valueToStore)
      if (typeof window !== 'undefined') {
        window.localStorage.setItem(key, JSON.stringify(valueToStore))
      }
    } catch (error) {
      console.warn(`useLocalStorage: не удалось записать ключ "${key}" в localStorage`, error)
    }
  }

  // Опционально: слушать изменения localStorage из других вкладок
  useEffect(() => {
    const handleStorage = (event: StorageEvent) => {
      if (event.key === key && event.newValue) {
        setStoredValue(JSON.parse(event.newValue))
      }
    }
    window.addEventListener('storage', handleStorage)
    return () => window.removeEventListener('storage', handleStorage)
  }, [key])

  return [storedValue, setValue] as const
}
