// src/widgets/Voting/VoteTallyProgress.tsx

import React from 'react';
import { useVoteTally } from '@/entities/voting/hooks/useVoteTally';
import { useTranslation } from 'react-i18next';
import { ProgressBar } from '@/shared/ui/ProgressBar';
import { Tooltip } from '@/shared/ui/Tooltip';
import { Gauge, Users, CheckCircle, XCircle, AlertTriangle } from 'lucide-react';
import styles from './styles/VoteTallyProgress.module.css';

interface VoteTallyProgressProps {
  proposalId: string;
  quorum: number; // в процентах, например 60
}

export const VoteTallyProgress: React.FC<VoteTallyProgressProps> = ({ proposalId, quorum }) => {
  const { t } = useTranslation();
  const { isLoading, yesVotes, noVotes, abstainVotes, totalEligiblePower, countedPower, isFinalized } = useVoteTally(proposalId);

  const totalVotes = yesVotes + noVotes + abstainVotes;
  const turnoutPercent = totalVotes / totalEligiblePower * 100;
  const yesPercent = yesVotes / totalEligiblePower * 100;
  const noPercent = noVotes / totalEligiblePower * 100;
  const abstainPercent = abstainVotes / totalEligiblePower * 100;
  const countedPercent = countedPower / totalEligiblePower * 100;
  const quorumReached = turnoutPercent >= quorum;

  const renderProgress = () => {
    return (
      <div className={styles.progressContainer}>
        <ProgressBar
          segments={[
            { percent: yesPercent, color: 'var(--green)', label: t('votes.yes') },
            { percent: noPercent, color: 'var(--red)', label: t('votes.no') },
            { percent: abstainPercent, color: 'var(--yellow)', label: t('votes.abstain') },
          ]}
          showPercent
        />
        <div className={styles.progressMeta}>
          <Tooltip content={t('votes.tooltip.totalVotes')}>
            <div className={styles.metaItem}>
              <Users size={16} />
              {t('votes.total')}: {totalVotes} / {totalEligiblePower}
            </div>
          </Tooltip>
          <Tooltip content={t('votes.tooltip.counted')}>
            <div className={styles.metaItem}>
              <Gauge size={16} />
              {t('votes.counted')}: {countedPower} ({countedPercent.toFixed(1)}%)
            </div>
          </Tooltip>
          <Tooltip content={t('votes.tooltip.quorum')}>
            <div className={styles.metaItem}>
              {quorumReached ? (
                <CheckCircle size={16} color="green" />
              ) : (
                <AlertTriangle size={16} color="orange" />
              )}
              {t('votes.quorum')}: {quorum}% → {turnoutPercent.toFixed(1)}%
            </div>
          </Tooltip>
        </div>
      </div>
    );
  };

  return (
    <div className={styles.wrapper}>
      <h4 className={styles.title}>{t('votes.tallyTitle')}</h4>
      {isLoading ? (
        <div className={styles.loading}>{t('loading')}...</div>
      ) : (
        <>
          {renderProgress()}
          {isFinalized && (
            <div className={styles.finalStatus}>
              {yesVotes > noVotes ? (
                <span className={styles.resultPassed}>{t('votes.passed')}</span>
              ) : (
                <span className={styles.resultRejected}>{t('votes.rejected')}</span>
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
};
