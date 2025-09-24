import { useState, useEffect } from 'react'

/**
 * useDebounce - возвращает значение с задержкой (debounce)
 * @param value — значение, которое нужно "задебаунсить"
 * @param delay — задержка в миллисекундах (по умолчанию 300)
 * @returns — дебаунсенное значение
 */
export function useDebounce<T>(value: T, delay = 300): T {
  const [debouncedValue, setDebouncedValue] = useState<T>(value)

  useEffect(() => {
    const handler = setTimeout(() => {
      setDebouncedValue(value)
    }, delay)

    return () => {
      clearTimeout(handler)
    }
  }, [value, delay])

  return debouncedValue
}
