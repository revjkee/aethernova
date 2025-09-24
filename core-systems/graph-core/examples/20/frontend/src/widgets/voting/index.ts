// src/widgets/Voting/index.ts

// Центральные промышленные Voting-компоненты

export { LiveVoteFeed } from './LiveVoteFeed'
export { ConstitutionReferenceLink } from './ConstitutionReferenceLink'
export { EmergencyVoteAlert } from './EmergencyVoteAlert'
export { VotingSimulationPreview } from './VotingSimulationPreview'
export { VoterRightRevocationWarning } from './VoterRightRevocationWarning'
export { VoteAuditLogSnippet } from './VoteAuditLogSnippet'
export { VoteConsensusStatus } from './VoteConsensusStatus'
export { VotingMethodSelector } from './VotingMethodSelector'
export { ReVoteOpportunityAlert } from './ReVoteOpportunityAlert'
export { VoteAnomalyFlag } from './VoteAnomalyFlag'
export { WidgetLoader } from './WidgetLoader'

// Дополнительные виджеты (при наличии)
export { VotingMethodInfoModal } from './VotingMethodInfoModal'

// Утилиты и типы (если используются глобально)
export type { AnomalyFlag } from './VoteAnomalyFlag'
export type { ReVoteStatus } from './ReVoteOpportunityAlert'

// Маппинг ленивых компонентов (для dynamic-import-based систем)
export const VotingWidgetLazyMap = {
  LiveVoteFeed: () => import('./LiveVoteFeed'),
  ConstitutionReferenceLink: () => import('./ConstitutionReferenceLink'),
  EmergencyVoteAlert: () => import('./EmergencyVoteAlert'),
  VotingSimulationPreview: () => import('./VotingSimulationPreview'),
  VoterRightRevocationWarning: () => import('./VoterRightRevocationWarning'),
  VoteAuditLogSnippet: () => import('./VoteAuditLogSnippet'),
  VoteConsensusStatus: () => import('./VoteConsensusStatus'),
  VotingMethodSelector: () => import('./VotingMethodSelector'),
  ReVoteOpportunityAlert: () => import('./ReVoteOpportunityAlert'),
  VoteAnomalyFlag: () => import('./VoteAnomalyFlag'),
  WidgetLoader: () => import('./WidgetLoader'),
  VotingMethodInfoModal: () => import('./VotingMethodInfoModal')
}

// Список для использования в генераторах UI, fallback системах или лентах управления
export const VotingWidgetList = [
  'LiveVoteFeed',
  'ConstitutionReferenceLink',
  'EmergencyVoteAlert',
  'VotingSimulationPreview',
  'VoterRightRevocationWarning',
  'VoteAuditLogSnippet',
  'VoteConsensusStatus',
  'VotingMethodSelector',
  'ReVoteOpportunityAlert',
  'VoteAnomalyFlag'
] as const

export type VotingWidgetKey = typeof VotingWidgetList[number]
