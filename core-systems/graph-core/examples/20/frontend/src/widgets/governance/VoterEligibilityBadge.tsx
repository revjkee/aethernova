import React from 'react';
import { Badge } from '@/components/ui/badge';
import { ShieldCheck, XCircle, HelpCircle, EyeOff, Lock } from 'lucide-react';
import { useUserContext } from '@/context/UserContext';
import { useEligibilityChecker } from '@/hooks/useEligibilityChecker';
import styles from './styles/VoterEligibilityBadge.module.css';
import classNames from 'classnames';

export type EligibilityStatus =
  | 'eligible_dao'
  | 'eligible_token'
  | 'eligible_kyc'
  | 'eligible_zk'
  | 'ineligible'
  | 'unknown';

interface VoterEligibilityBadgeProps {
  proposalId: string;
  compact?: boolean;
}

const statusMap: Record<EligibilityStatus, { label: string; icon: JSX.Element; className: string }> = {
  eligible_dao: {
    label: 'Допущен (DAO)',
    icon: <ShieldCheck size={14} />,
    className: styles.dao
  },
  eligible_token: {
    label: 'Допущен (Token)',
    icon: <ShieldCheck size={14} />,
    className: styles.token
  },
  eligible_kyc: {
    label: 'KYC верифицирован',
    icon: <ShieldCheck size={14} />,
    className: styles.kyc
  },
  eligible_zk: {
    label: 'ZK-подтверждён',
    icon: <EyeOff size={14} />,
    className: styles.zk
  },
  ineligible: {
    label: 'Нет допуска',
    icon: <XCircle size={14} />,
    className: styles.ineligible
  },
  unknown: {
    label: 'Проверка...',
    icon: <HelpCircle size={14} />,
    className: styles.unknown
  }
};

export const VoterEligibilityBadge: React.FC<VoterEligibilityBadgeProps> = ({ proposalId, compact = false }) => {
  const { user } = useUserContext();
  const { status, loading } = useEligibilityChecker(user?.id, proposalId);

  const resolvedStatus: EligibilityStatus = loading ? 'unknown' : status;

  const { label, icon, className } = statusMap[resolvedStatus];

  return (
    <div className={classNames(styles.badgeContainer, className)}>
      <Badge variant="outline" className={styles.badge}>
        {icon}
        {!compact && <span>{label}</span>}
      </Badge>
    </div>
  );
};

export default VoterEligibilityBadge;
