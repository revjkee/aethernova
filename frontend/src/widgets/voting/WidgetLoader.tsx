// src/widgets/Voting/WidgetLoader.tsx

import React, { Suspense, useMemo, useEffect, useState } from 'react'
import { Spinner } from '@/shared/components/Spinner'
import { useZKAuth } from '@/shared/hooks/useZKAuth'
import { useLatencyTracker } from '@/shared/hooks/useLatencyTracker'
import { useAuditLogger } from '@/shared/hooks/useAuditLogger'
import { cn } from '@/shared/utils/classNames'

interface WidgetLoaderProps {
  userId: string
  widget: 'LiveVoteFeed' | 'ConstitutionReferenceLink' | 'EmergencyVoteAlert' |
          'VotingSimulationPreview' | 'VoterRightRevocationWarning' |
          'VoteAuditLogSnippet' | 'VoteConsensusStatus' | 'VotingMethodSelector' |
          'ReVoteOpportunityAlert' | 'VoteAnomalyFlag'
  onFail?: () => void
}

const widgetMap: Record<string, React.LazyExoticComponent<React.FC>> = {
  LiveVoteFeed: React.lazy(() => import('./LiveVoteFeed')),
  ConstitutionReferenceLink: React.lazy(() => import('./ConstitutionReferenceLink')),
  EmergencyVoteAlert: React.lazy(() => import('./EmergencyVoteAlert')),
  VotingSimulationPreview: React.lazy(() => import('./VotingSimulationPreview')),
  VoterRightRevocationWarning: React.lazy(() => import('./VoterRightRevocationWarning')),
  VoteAuditLogSnippet: React.lazy(() => import('./VoteAuditLogSnippet')),
  VoteConsensusStatus: React.lazy(() => import('./VoteConsensusStatus')),
  VotingMethodSelector: React.lazy(() => import('./VotingMethodSelector')),
  ReVoteOpportunityAlert: React.lazy(() => import('./ReVoteOpportunityAlert')),
  VoteAnomalyFlag: React.lazy(() => import('./VoteAnomalyFlag')),
}

const accessMap: Record<string, string> = {
  LiveVoteFeed: 'vote_feed',
  ConstitutionReferenceLink: 'constitution_access',
  EmergencyVoteAlert: 'emergency_vote',
  VotingSimulationPreview: 'simulate_vote',
  VoterRightRevocationWarning: 'revocation_notice',
  VoteAuditLogSnippet: 'audit_log',
  VoteConsensusStatus: 'consensus_status',
  VotingMethodSelector: 'method_selector',
  ReVoteOpportunityAlert: 'revote_check',
  VoteAnomalyFlag: 'anomaly_flags',
}

export const WidgetLoader: React.FC<WidgetLoaderProps> = ({ userId, widget, onFail }) => {
  const [zkAllowed, setZkAllowed] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const { verifyZKProof } = useZKAuth()
  const { trackLatency } = useLatencyTracker(`Widget:${widget}`)
  const audit = useAuditLogger()

  const Component = useMemo(() => widgetMap[widget], [widget])
  const zkPurpose = accessMap[widget]

  useEffect(() => {
    const run = async () => {
      try {
        const start = Date.now()
        const result = await verifyZKProof({ userId, purpose: zkPurpose })

        if (!result) {
          audit({
            event: 'widget_access_denied',
            userId,
            timestamp: Date.now(),
            metadata: { widget, reason: 'ZK deny' }
          })
          setError('Доступ к виджету ограничен')
          if (onFail) onFail()
        } else {
          setZkAllowed(true)
          trackLatency(Date.now() - start)

          audit({
            event: 'widget_loaded',
            userId,
            timestamp: Date.now(),
            metadata: { widget }
          })
        }
      } catch (e) {
        setError('Ошибка при ZK-проверке')
        if (onFail) onFail()
      }
    }

    run()
  }, [userId, widget, zkPurpose, verifyZKProof, audit, onFail, trackLatency])

  if (error) {
    return (
      <div className="text-center text-sm text-red-500 mt-2">{error}</div>
    )
  }

  if (!zkAllowed) {
    return (
      <div className="text-center text-sm text-gray-400 mt-2">Загрузка...</div>
    )
  }

  return (
    <Suspense fallback={<div className="flex justify-center p-4"><Spinner /></div>}>
      <Component />
    </Suspense>
  )
}
