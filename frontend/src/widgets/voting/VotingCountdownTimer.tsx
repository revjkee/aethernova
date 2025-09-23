// src/widgets/Voting/VotingCountdownTimer.tsx

import React, { useEffect, useState, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import clsx from 'clsx';
import { getVotingDeadline } from '@/entities/voting/api/votingService';
import { Alert } from '@/shared/ui/Alert';
import { formatDuration, intervalToDuration } from 'date-fns';
import { motion, AnimatePresence } from 'framer-motion';
import styles from './styles/VotingCountdownTimer.module.css';

interface VotingCountdownTimerProps {
  proposalId: string;
  onExpire?: () => void;
  criticalThresholdSec?: number;
}

export const VotingCountdownTimer: React.FC<VotingCountdownTimerProps> = ({
  proposalId,
  onExpire,
  criticalThresholdSec = 300,
}) => {
  const { t } = useTranslation();
  const [remaining, setRemaining] = useState<number | null>(null);
  const [expired, setExpired] = useState(false);
  const intervalRef = useRef<NodeJS.Timer | null>(null);

  useEffect(() => {
    const syncTime = async () => {
      try {
        const deadline = await getVotingDeadline(proposalId);
        if (!deadline) {
          setRemaining(null);
          return;
        }
        const now = new Date();
        const diff = new Date(deadline).getTime() - now.getTime();
        setRemaining(diff > 0 ? Math.floor(diff / 1000) : 0);
      } catch (e) {
        console.error('Failed to fetch deadline', e);
      }
    };

    syncTime();

    intervalRef.current = setInterval(() => {
      setRemaining((prev) => {
        if (prev === null) return null;
        if (prev <= 1) {
          clearInterval(intervalRef.current!);
          setExpired(true);
          onExpire?.();
          return 0;
        }
        return prev - 1;
      });
    }, 1000);

    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [proposalId, onExpire]);

  if (remaining === null) {
    return <Alert type="error">{t('voting.timer.unavailable')}</Alert>;
  }

  if (expired) {
    return (
      <motion.div
        initial={{ opacity: 0.3 }}
        animate={{ opacity: 1 }}
        className={clsx(styles.timer, styles.expired)}
      >
        {t('voting.timer.expired')}
      </motion.div>
    );
  }

  const duration = intervalToDuration({ start: 0, end: remaining * 1000 });
  const formatted = formatDuration(duration, { format: ['hours', 'minutes', 'seconds'] });

  const isCritical = remaining <= criticalThresholdSec;

  return (
    <div className={clsx(styles.timer, isCritical && styles.critical)}>
      <AnimatePresence>
        <motion.span
          key={remaining}
          initial={{ opacity: 0, y: -2 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: 2 }}
          transition={{ duration: 0.3 }}
        >
          {t('voting.timer.remaining', { time: formatted })}
        </motion.span>
      </AnimatePresence>
    </div>
  );
};
