import { useState, useCallback } from 'react'

/**
 * useModal — хук для управления видимостью модального окна
 * @returns объект с состоянием и функциями управления: { isOpen, open, close, toggle }
 */
export function useModal() {
  const [isOpen, setIsOpen] = useState(false)

  const open = useCallback(() => setIsOpen(true), [])
  const close = useCallback(() => setIsOpen(false), [])
  const toggle = useCallback(() => setIsOpen(prev => !prev), [])

  return { isOpen, open, close, toggle }
}
