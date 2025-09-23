// src/widgets/Voting/VoteCastButton.tsx

import React, { useCallback, useState } from 'react';
import { Button } from '@/shared/ui/Button';
import { useAccount } from '@/entities/wallet/hooks/useAccount';
import { useTransactionStatus } from '@/entities/tx/hooks/useTransactionStatus';
import { useCastVote } from '@/entities/governance/api/useCastVote';
import { useQuorumValidation } from '@/entities/governance/hooks/useQuorumValidation';
import { useAIIntentChecker } from '@/entities/ai/hooks/useAIIntentChecker';
import { toast } from '@/shared/lib/toast';
import { Spinner } from '@/shared/ui/Spinner';
import { Logger } from '@/shared/lib/logger';
import { validateKYC } from '@/entities/security/utils/validateKYC';
import { VoteOption, ProposalID } from '@/shared/types/governance';
import styles from './styles/VoteCastButton.module.css';

type Props = {
  proposalId: ProposalID;
  option: VoteOption;
  disabled?: boolean;
};

export const VoteCastButton: React.FC<Props> = ({ proposalId, option, disabled }) => {
  const { address } = useAccount();
  const { isLoading, submitVote } = useCastVote();
  const { validateQuorum } = useQuorumValidation(proposalId);
  const { checkIntent } = useAIIntentChecker();
  const { status, setStatus } = useTransactionStatus();
  const [processing, setProcessing] = useState(false);

  const handleVote = useCallback(async () => {
    if (!address) {
      toast.error('Адрес кошелька не найден');
      return;
    }

    if (disabled || processing || isLoading) return;

    try {
      setProcessing(true);

      const kycOk = await validateKYC(address);
      if (!kycOk) {
        toast.error('KYC-проверка не пройдена');
        return;
      }

      const intentOk = await checkIntent({ proposalId, vote: option });
      if (!intentOk.valid) {
        toast.warning(`AI-фильтр: ${intentOk.reason}`);
        return;
      }

      const quorumStatus = await validateQuorum();
      if (!quorumStatus.valid) {
        toast.warning('Кворум не достигнут. Голосование невозможно.');
        return;
      }

      setStatus('pending');
      const txHash = await submitVote({ proposalId, vote: option });
      Logger.info('Голосование отправлено', { txHash, proposalId, option });

      setStatus('success');
      toast.success('Голос успешно отправлен');
    } catch (error) {
      Logger.error('Ошибка при голосовании', error);
      setStatus('error');
      toast.error('Ошибка отправки голоса');
    } finally {
      setProcessing(false);
    }
  }, [
    address,
    option,
    disabled,
    proposalId,
    isLoading,
    processing,
    validateQuorum,
    submitVote,
    checkIntent,
    setStatus,
  ]);

  return (
    <Button
      variant="primary"
      onClick={handleVote}
      className={styles.voteButton}
      disabled={disabled || isLoading || processing || status === 'pending'}
    >
      {processing || status === 'pending' ? (
        <Spinner size="sm" />
      ) : (
        `Проголосовать: ${option.toUpperCase()}`
      )}
    </Button>
  );
};
