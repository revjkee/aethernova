// src/widgets/Voting/VotingEligibilityIndicator.tsx

import React from 'react';
import { useVotingEligibility } from '@/entities/voting/hooks/useVotingEligibility';
import { useTranslation } from 'react-i18next';
import { Loader } from '@/shared/ui/Loader';
import { Badge } from '@/shared/ui/Badge';
import { Tooltip } from '@/shared/ui/Tooltip';
import { ShieldCheck, AlertTriangle, Ban, KeyRound } from 'lucide-react';
import styles from './styles/VotingEligibilityIndicator.module.css';

interface VotingEligibilityIndicatorProps {
  voterAddress: string;
}

export const VotingEligibilityIndicator: React.FC<VotingEligibilityIndicatorProps> = ({ voterAddress }) => {
  const { t } = useTranslation();
  const { status, isLoading, reasons, kycLevel, tokenBalance, requiredStake, chainId, daoMembershipStatus } = useVotingEligibility(voterAddress);

  const renderIcon = () => {
    if (isLoading) return <Loader size="sm" />;
    if (status === 'eligible') return <ShieldCheck color="green" size={18} />;
    if (status === 'pending') return <AlertTriangle color="orange" size={18} />;
    return <Ban color="red" size={18} />;
  };

  const renderTooltip = () => {
    if (isLoading) return t('checkingEligibility');
    if (status === 'eligible') return t('eligibleToVote');
    if (status === 'pending') return t('eligibilityPendingReview');
    if (status === 'ineligible' && reasons.length > 0)
      return reasons.map((r, i) => <div key={i}>{t(r)}</div>);
    return t('notEligibleUnknownReason');
  };

  return (
    <Tooltip content={renderTooltip()}>
      <div className={styles.indicatorContainer}>
        {renderIcon()}
        <span className={styles.statusText}>
          {t(`voterStatus.${status}`)}
        </span>
        {kycLevel !== null && (
          <Badge variant="info" icon={<KeyRound size={12} />}>
            {t('kycLevel')} {kycLevel}
          </Badge>
        )}
        {typeof tokenBalance === 'number' && typeof requiredStake === 'number' && (
          <Badge variant={tokenBalance >= requiredStake ? 'green' : 'red'}>
            {t('stake')}: {tokenBalance}/{requiredStake}
          </Badge>
        )}
        {daoMembershipStatus && (
          <Badge variant={daoMembershipStatus === 'active' ? 'blue' : 'grey'}>
            {t('daoMembership')}: {t(`membership.${daoMembershipStatus}`)}
          </Badge>
        )}
        <span className={styles.chainId}>Chain: {chainId}</span>
      </div>
    </Tooltip>
  );
};
