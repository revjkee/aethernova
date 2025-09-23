// src/widgets/Governance/WidgetLoader.tsx

import React, { Suspense, lazy, useMemo } from 'react';
import { Skeleton } from '@/components/ui/skeleton';
import { ErrorBoundary } from '@/components/core/ErrorBoundary';
import { logWidgetLoad, logWidgetError } from '@/lib/telemetry/governanceLogger';
import { useWidgetPermissions } from '@/hooks/auth/useWidgetPermissions';
import { useFeatureFlag } from '@/hooks/flags/useFeatureFlag';
import { cn } from '@/lib/utils';
import { WidgetSecurityWrapper } from './security/WidgetSecurityWrapper';

type GovernanceWidget =
  | 'ProposalListWidget'
  | 'ProposalDetailsView'
  | 'VoteResultChart'
  | 'VoteActionButtons'
  | 'VoterEligibilityBadge'
  | 'ZKVoteVerifier'
  | 'DelegateListWidget'
  | 'DelegateActivityChart'
  | 'DelegateTrustScore'
  | 'GovernanceTimeline'
  | 'GovernanceKPIWidget'
  | 'TreasuryImpactGraph'
  | 'ProposalImpactForecast'
  | 'QuorumStatusIndicator'
  | 'VoteIntegrityStatus'
  | 'GovernanceComplianceChecker'
  | 'ProposalCreatorPanel'
  | 'MultiChainVoteBridgeStatus'
  | 'AgentGovernanceHeatmap'
  | 'EthicsApprovalMeter'
  | 'VoterReputationIndicator'
  | 'PolicyAmendmentTracker'
  | 'DAOHealthScoreWidget'
  | 'GovernanceActionLog'
  | 'ProposalVotingCountdown'
  | 'VotingModeSelector'
  | 'ConstitutionReferencePanel'
  | 'DAOEmergencyActionsPanel'
  | 'ProposalSimulationPreview'
  | 'GovernanceNotificationBadge'
  | 'ConsensusThresholdVisualizer'
  | 'ProposalStakeRequirement';

interface WidgetLoaderProps {
  widgetName: GovernanceWidget;
  className?: string;
  fallbackHeight?: number;
  requirePermission?: boolean;
}

const WIDGETS_MAP: Record<GovernanceWidget, () => Promise<{ default: React.ComponentType<any> }>> = {
  ProposalListWidget: () => import('./ProposalListWidget'),
  ProposalDetailsView: () => import('./ProposalDetailsView'),
  VoteResultChart: () => import('./VoteResultChart'),
  VoteActionButtons: () => import('./VoteActionButtons'),
  VoterEligibilityBadge: () => import('./VoterEligibilityBadge'),
  ZKVoteVerifier: () => import('./ZKVoteVerifier'),
  DelegateListWidget: () => import('./DelegateListWidget'),
  DelegateActivityChart: () => import('./DelegateActivityChart'),
  DelegateTrustScore: () => import('./DelegateTrustScore'),
  GovernanceTimeline: () => import('./GovernanceTimeline'),
  GovernanceKPIWidget: () => import('./GovernanceKPIWidget'),
  TreasuryImpactGraph: () => import('./TreasuryImpactGraph'),
  ProposalImpactForecast: () => import('./ProposalImpactForecast'),
  QuorumStatusIndicator: () => import('./QuorumStatusIndicator'),
  VoteIntegrityStatus: () => import('./VoteIntegrityStatus'),
  GovernanceComplianceChecker: () => import('./GovernanceComplianceChecker'),
  ProposalCreatorPanel: () => import('./ProposalCreatorPanel'),
  MultiChainVoteBridgeStatus: () => import('./MultiChainVoteBridgeStatus'),
  AgentGovernanceHeatmap: () => import('./AgentGovernanceHeatmap'),
  EthicsApprovalMeter: () => import('./EthicsApprovalMeter'),
  VoterReputationIndicator: () => import('./VoterReputationIndicator'),
  PolicyAmendmentTracker: () => import('./PolicyAmendmentTracker'),
  DAOHealthScoreWidget: () => import('./DAOHealthScoreWidget'),
  GovernanceActionLog: () => import('./GovernanceActionLog'),
  ProposalVotingCountdown: () => import('./ProposalVotingCountdown'),
  VotingModeSelector: () => import('./VotingModeSelector'),
  ConstitutionReferencePanel: () => import('./ConstitutionReferencePanel'),
  DAOEmergencyActionsPanel: () => import('./DAOEmergencyActionsPanel'),
  ProposalSimulationPreview: () => import('./ProposalSimulationPreview'),
  GovernanceNotificationBadge: () => import('./GovernanceNotificationBadge'),
  ConsensusThresholdVisualizer: () => import('./ConsensusThresholdVisualizer'),
  ProposalStakeRequirement: () => import('./ProposalStakeRequirement'),
};

export const WidgetLoader: React.FC<WidgetLoaderProps> = ({
  widgetName,
  className,
  fallbackHeight = 180,
  requirePermission = false,
}) => {
  const LazyWidget = useMemo(() => lazy(WIDGETS_MAP[widgetName]), [widgetName]);
  const { isAllowed } = useWidgetPermissions(widgetName);
  const { enabled: isFeatureEnabled } = useFeatureFlag(`widgets.${widgetName}`);

  if (requirePermission && !isAllowed) {
    return null;
  }

  if (!isFeatureEnabled) {
    return null;
  }

  return (
    <ErrorBoundary
      onError={(error) => {
        logWidgetError(widgetName, error);
      }}
      fallback={
        <div className="p-4 text-sm text-red-600 bg-red-100 border border-red-300 rounded-md">
          Не удалось загрузить компонент <strong>{widgetName}</strong>.
        </div>
      }
    >
      <Suspense fallback={<Skeleton className={cn('w-full', `h-[${fallbackHeight}px]`)} />}>
        <WidgetSecurityWrapper widget={widgetName}>
          <div className={cn('w-full', className)}>
            <LazyWidget />
          </div>
        </WidgetSecurityWrapper>
      </Suspense>
    </ErrorBoundary>
  );
};
