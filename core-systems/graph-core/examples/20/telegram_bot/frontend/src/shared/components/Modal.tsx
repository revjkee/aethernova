// src/shared/components/ui/Modal.tsx
import { FC, ReactNode, useEffect } from 'react'
import { createPortal } from 'react-dom'
import { cn } from '@/shared/lib/classNames'

interface ModalProps {
  isOpen: boolean
  onClose: () => void
  title?: string
  children: ReactNode
  className?: string
}

const modalRoot = document.getElementById('modal-root') || document.body

export const Modal: FC<ModalProps> = ({ isOpen, onClose, title, children, className }) => {
  useEffect(() => {
    const onEsc = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    if (isOpen) {
      document.body.style.overflow = 'hidden'
      window.addEventListener('keydown', onEsc)
    } else {
      document.body.style.overflow = ''
    }
    return () => {
      document.body.style.overflow = ''
      window.removeEventListener('keydown', onEsc)
    }
  }, [isOpen, onClose])

  if (!isOpen) return null

  return createPortal(
    <div
      className={cn(
        'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50',
        className
      )}
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-labelledby="modal-title"
    >
      <div
        className="bg-white rounded-2xl p-6 max-w-lg w-full shadow-lg"
        onClick={e => e.stopPropagation()}
      >
        {title && <h2 id="modal-title" className="text-xl font-semibold mb-4">{title}</h2>}
        <div>{children}</div>
      </div>
    </div>,
    modalRoot
  )
}
