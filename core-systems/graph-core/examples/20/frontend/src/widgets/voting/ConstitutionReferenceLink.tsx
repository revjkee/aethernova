// src/widgets/Voting/ConstitutionReferenceLink.tsx

import React, { useCallback, useEffect, useState } from 'react'
import { cn } from '@/shared/utils/classNames'
import { useTheme } from '@/shared/hooks/useTelegramTheme'
import { useZKAuth } from '@/shared/hooks/useZKAuth'
import { useAuditLogger } from '@/shared/hooks/useAuditLogger'
import { useModal } from '@/shared/hooks/useModal'
import { Spinner } from '@/shared/components/Spinner'
import { LegalViewerModal } from '@/widgets/Voting/LegalViewerModal'
import { trackEvent } from '@/shared/telemetry/trackEvent'
import { fetchConstitution } from '@/services/legalService'

interface ConstitutionLinkProps {
  proposalId: string
  userId: string
  className?: string
}

export const ConstitutionReferenceLink: React.FC<ConstitutionLinkProps> = ({
  proposalId,
  userId,
  className
}) => {
  const { theme } = useTheme()
  const [loading, setLoading] = useState(false)
  const [constitutionUrl, setConstitutionUrl] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const { verifyZKProof } = useZKAuth()
  const { openModal, closeModal, isOpen } = useModal('constitution-modal')
  const logAudit = useAuditLogger()

  const handleClick = useCallback(async () => {
    setLoading(true)
    setError(null)
    trackEvent('constitution_link_click', { proposalId, userId })

    const verified = await verifyZKProof({ purpose: 'access_constitution', userId })
    if (!verified) {
      setError('Проверка доступа не пройдена.')
      setLoading(false)
      return
    }

    try {
      const response = await fetchConstitution(proposalId)
      if (!response?.url) throw new Error('Документ не найден.')
      setConstitutionUrl(response.url)

      logAudit({
        event: 'access_constitution',
        userId,
        target: proposalId,
        timestamp: Date.now(),
        metadata: { source: 'vote_widget' }
      })

      openModal()
    } catch (err) {
      setError('Не удалось загрузить устав. Попробуйте позже.')
    } finally {
      setLoading(false)
    }
  }, [proposalId, userId, verifyZKProof, logAudit, openModal])

  useEffect(() => {
    if (!isOpen) setConstitutionUrl(null)
  }, [isOpen])

  return (
    <div className={cn('flex flex-col items-center justify-center', className)}>
      <button
        onClick={handleClick}
        disabled={loading}
        className={cn(
          'px-4 py-2 rounded-md border text-sm font-medium transition-all duration-300 shadow-sm',
          theme === 'dark'
            ? 'bg-gray-800 text-white border-gray-700 hover:bg-gray-700'
            : 'bg-white text-gray-900 border-gray-300 hover:bg-gray-100'
        )}
      >
        {loading ? <Spinner size="sm" /> : 'Посмотреть устав DAO'}
      </button>

      {error && (
        <p className="mt-2 text-sm text-red-500" role="alert">
          {error}
        </p>
      )}

      {isOpen && constitutionUrl && (
        <LegalViewerModal
          isOpen={isOpen}
          onClose={closeModal}
          documentUrl={constitutionUrl}
          title="Устав DAO"
          trackingId={`constitution-${proposalId}`}
        />
      )}
    </div>
  )
}
