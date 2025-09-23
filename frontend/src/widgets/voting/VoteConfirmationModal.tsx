import React, { useState } from 'react';
import { Modal } from '@/shared/components/Modal';
import { Button } from '@/shared/components/Button';
import { Loader } from '@/shared/components/Loader';
import { VoteOptionBadge } from '@/shared/components/VoteOptionBadge';
import { ImpactProjection } from '@/shared/components/ImpactProjection';
import { useZKIdentity } from '@/shared/hooks/useZKIdentity';
import { useAuditLogger } from '@/shared/hooks/useAuditLogger';
import { castVote } from '@/services/governance/voteService';
import { getTimeFormatted } from '@/utils/timeUtils';

type VoteConfirmationModalProps = {
  isOpen: boolean;
  onClose: () => void;
  onConfirmed: () => void;
  userAddress: string;
  proposalId: string;
  voteOption: 'yes' | 'no' | 'abstain';
  voteWeight: number;
  autoClose?: boolean;
};

export const VoteConfirmationModal: React.FC<VoteConfirmationModalProps> = ({
  isOpen,
  onClose,
  onConfirmed,
  userAddress,
  proposalId,
  voteOption,
  voteWeight,
  autoClose = true
}) => {
  const { identityHash, zkProofAvailable } = useZKIdentity(userAddress);
  const logAudit = useAuditLogger();

  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleVote = async () => {
    setIsSubmitting(true);
    setError(null);
    try {
      await castVote({
        proposalId,
        voterAddress: userAddress,
        vote: voteOption,
        weight: voteWeight,
        zkVerified: zkProofAvailable,
        identityHash,
        timestamp: new Date().toISOString()
      });

      logAudit({
        type: 'VOTE_CONFIRMED',
        user: userAddress,
        proposalId,
        option: voteOption,
        zkVerified: zkProofAvailable,
        identityHash,
        voteWeight,
        timestamp: new Date().toISOString()
      });

      if (autoClose) onClose();
      onConfirmed();
    } catch (err) {
      setError('Ошибка при подтверждении голоса. Повторите попытку.');
      logAudit({
        type: 'VOTE_CONFIRMATION_ERROR',
        user: userAddress,
        proposalId,
        error: err.message,
        option: voteOption
      });
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <Modal
      open={isOpen}
      onClose={onClose}
      title="Подтверждение голосования"
    >
      <div className="space-y-4 text-sm text-gray-700 dark:text-gray-300">
        <div>
          Вы уверены, что хотите проголосовать <VoteOptionBadge option={voteOption} />?
        </div>

        <div>
          Вес голоса: <strong>{voteWeight}</strong>
        </div>

        <div>
          Ваша ZK-идентификация: {zkProofAvailable ? 'Подтверждена' : 'Не доступна'}
        </div>

        <div>
          Время голосования: {getTimeFormatted(new Date().toISOString())}
        </div>

        <ImpactProjection
          proposalId={proposalId}
          voteOption={voteOption}
          userAddress={userAddress}
        />

        {error && (
          <div className="text-sm text-red-600 dark:text-red-400">{error}</div>
        )}

        <div className="flex justify-end gap-3 mt-6">
          <Button variant="ghost" onClick={onClose} disabled={isSubmitting}>
            Отменить
          </Button>
          <Button
            variant="primary"
            onClick={handleVote}
            loading={isSubmitting}
            disabled={isSubmitting}
          >
            Подтвердить голос
          </Button>
        </div>

        {isSubmitting && <Loader label="Отправка голоса..." />}
      </div>
    </Modal>
  );
};

export default VoteConfirmationModal;
