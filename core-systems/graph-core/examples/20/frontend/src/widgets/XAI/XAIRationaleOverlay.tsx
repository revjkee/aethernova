// src/widgets/XAI/XAIRationaleOverlay.tsx

import React, { useEffect, useState } from 'react'
import { createPortal } from 'react-dom'
import { AnimatePresence, motion } from 'framer-motion'
import { useXAIContext } from '@/shared/context/XAIContext'
import { fetchRationaleForDecision } from '@/services/xai/api'
import { ShieldAlert, Info } from 'lucide-react'
import { cn } from '@/shared/utils/cn'
import './XAIRationaleOverlay.css'

type XAIRationaleOverlayProps = {
  triggerSelector: string
  decisionId: string
  autoShow?: boolean
  onClose?: () => void
}

export const XAIRationaleOverlay: React.FC<XAIRationaleOverlayProps> = ({
  triggerSelector,
  decisionId,
  autoShow = true,
  onClose
}) => {
  const [rationale, setRationale] = useState<string | null>(null)
  const [visible, setVisible] = useState<boolean>(autoShow)
  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null)
  const { highlightDecisionTrace } = useXAIContext()

  useEffect(() => {
    const targetEl = document.querySelector(triggerSelector) as HTMLElement
    if (targetEl) setAnchorEl(targetEl)
  }, [triggerSelector])

  useEffect(() => {
    if (!decisionId) return
    fetchRationaleForDecision(decisionId)
      .then(setRationale)
      .catch(() => setRationale('Объяснение недоступно.'))
  }, [decisionId])

  const handleClose = () => {
    setVisible(false)
    onClose?.()
  }

  if (!anchorEl) return null

  const rect = anchorEl.getBoundingClientRect()
  const portalTarget = document.getElementById('xai-overlay-root')
  if (!portalTarget) return null

  return createPortal(
    <AnimatePresence>
      {visible && (
        <motion.div
          className={cn('xai-rationale-overlay')}
          initial={{ opacity: 0, y: -5 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -5 }}
          style={{
            top: rect.top + window.scrollY - 10,
            left: rect.left + rect.width + 12,
            maxWidth: 320
          }}
        >
          <div className="xai-overlay-content">
            <div className="xai-header">
              <Info size={16} />
              <span>Объяснение решения AI</span>
            </div>
            <div className="xai-body">
              {rationale ? (
                <p className="xai-text">{rationale}</p>
              ) : (
                <p className="xai-loading">Загрузка...</p>
              )}
            </div>
            <div className="xai-footer">
              <button onClick={handleClose} className="xai-close-btn">Закрыть</button>
              <button onClick={() => highlightDecisionTrace(decisionId)} className="xai-trace-btn">
                <ShieldAlert size={14} />
                Просмотреть reasoning
              </button>
            </div>
          </div>
        </motion.div>
      )}
    </AnimatePresence>,
    portalTarget
  )
}
