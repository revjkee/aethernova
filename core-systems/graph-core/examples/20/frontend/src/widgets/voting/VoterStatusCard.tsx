// src/widgets/Voting/VoterStatusCard.tsx

import React, { useMemo } from 'react';
import { Card } from '@/shared/ui/Card';
import { ProgressBar } from '@/shared/ui/ProgressBar';
import { TrustLevel } from '@/entities/trust/components/TrustLevel';
import { ReputationScore } from '@/entities/reputation/components/ReputationScore';
import { useVoterProfile } from '@/entities/voting/hooks/useVoterProfile';
import { useVoterAnalytics } from '@/entities/voting/hooks/useVoterAnalytics';
import { useTranslation } from 'react-i18next';
import { getChainLogo } from '@/shared/utils/chainVisuals';
import { Tooltip } from '@/shared/ui/Tooltip';
import { Badge } from '@/shared/ui/Badge';
import { AiVotingInsight } from '@/entities/ai/components/AiVotingInsight';
import styles from './styles/VoterStatusCard.module.css';

interface VoterStatusCardProps {
  voterAddress: string;
}

export const VoterStatusCard: React.FC<VoterStatusCardProps> = ({ voterAddress }) => {
  const { t } = useTranslation();
  const { profile, isLoading: loadingProfile } = useVoterProfile(voterAddress);
  const { metrics, isLoading: loadingAnalytics } = useVoterAnalytics(voterAddress);

  const isLoading = loadingProfile || loadingAnalytics;

  const chainLogo = useMemo(() => getChainLogo(profile?.chainId), [profile]);

  if (isLoading || !profile || !metrics) {
    return (
      <Card className={styles.card}>
        <div className={styles.loading}>{t('loadingStatus')}</div>
      </Card>
    );
  }

  return (
    <Card className={styles.card}>
      <div className={styles.header}>
        <div className={styles.identity}>
          <img src={chainLogo} alt="Chain" className={styles.chainIcon} />
          <span className={styles.address}>{voterAddress.slice(0, 6)}...{voterAddress.slice(-4)}</span>
          {profile.isDelegate && <Badge variant="info">{t('delegate')}</Badge>}
          {profile.isAIBacked && <Badge variant="purple">{t('aiAssisted')}</Badge>}
        </div>
        <div className={styles.stats}>
          <TrustLevel level={metrics.trustScore} />
          <ReputationScore score={metrics.reputation} />
        </div>
      </div>

      <div className={styles.body}>
        <div className={styles.metricBlock}>
          <span>{t('votingParticipation')}</span>
          <Tooltip content={t('votingParticipationHint')}>
            <ProgressBar value={metrics.participationRate} label={`${metrics.participationRate}%`} />
          </Tooltip>
        </div>

        <div className={styles.metricBlock}>
          <span>{t('consensusAlignment')}</span>
          <Tooltip content={t('consensusAlignmentHint')}>
            <ProgressBar value={metrics.consensusAlignment} label={`${metrics.consensusAlignment}%`} />
          </Tooltip>
        </div>

        <div className={styles.metricBlock}>
          <span>{t('stakeContribution')}</span>
          <Tooltip content={t('stakeContributionHint')}>
            <ProgressBar value={metrics.stakeShare} label={`${metrics.stakeShare}%`} />
          </Tooltip>
        </div>

        <div className={styles.metricBlock}>
          <span>{t('proposalsSubmitted')}</span>
          <span className={styles.numericValue}>{metrics.proposalsSubmitted}</span>
        </div>

        <div className={styles.metricBlock}>
          <span>{t('votesCast')}</span>
          <span className={styles.numericValue}>{metrics.totalVotes}</span>
        </div>

        <div className={styles.metricBlock}>
          <span>{t('lastActive')}</span>
          <span className={styles.numericValue}>{profile.lastActiveFormatted}</span>
        </div>

        <div className={styles.metricBlock}>
          <span>{t('delegatedVotes')}</span>
          <span className={styles.numericValue}>{metrics.votesDelegated}</span>
        </div>

        <div className={styles.metricBlock}>
          <span>{t('linkedIdentities')}</span>
          <span className={styles.numericValue}>{profile.linkedIds.length}</span>
        </div>
      </div>

      <div className={styles.aiInsight}>
        <AiVotingInsight voterAddress={voterAddress} />
      </div>
    </Card>
  );
};
