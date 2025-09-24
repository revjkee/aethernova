import React, { useState } from 'react';
import { castAbstainVote } from '@/services/governance/voteService';
import { useZKIdentity } from '@/shared/hooks/useZKIdentity';
import { useAuditLogger } from '@/shared/hooks/useAuditLogger';
import { Button } from '@/shared/components/Button';
import { Tooltip } from '@/shared/components/Tooltip';
import { ConfirmDialog } from '@/shared/components/ConfirmDialog';
import { InfoIcon } from '@/shared/components/icons/InfoIcon';
import { Loader } from '@/shared/components/Loader';
import { formatTimestamp } from '@/utils/timeUtils';

type AbstainVoteButtonProps = {
  userAddress: string;
  proposalId: string;
  isVotingOpen: boolean;
};

export const AbstainVoteButton: React.FC<AbstainVoteButtonProps> = ({
  userAddress,
  proposalId,
  isVotingOpen
}) => {
  const { identityHash, zkProofAvailable } = useZKIdentity(userAddress);
  const logAudit = useAuditLogger();

  const [confirmOpen, setConfirmOpen] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [hasVoted, setHasVoted] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleAbstain = async () => {
    setIsSubmitting(true);
    setError(null);
    try {
      await castAbstainVote({
        userAddress,
        proposalId,
        zkVerified: zkProofAvailable,
        reason: 'user_explicit_abstain',
        timestamp: new Date().toISOString(),
        identityHash
      });

      logAudit({
        type: 'ABSTAIN_VOTE_CAST',
        user: userAddress,
        proposalId,
        identityHash,
        zkVerified: zkProofAvailable,
        timestamp: new Date().toISOString()
      });

      setHasVoted(true);
    } catch (err) {
      setError('Ошибка при отправке голоса воздержания.');
      logAudit({
        type: 'ABSTAIN_VOTE_ERROR',
        user: userAddress,
        proposalId,
        error: err.message
      });
    } finally {
      setIsSubmitting(false);
      setConfirmOpen(false);
    }
  };

  if (hasVoted) {
    return (
      <div className="text-sm text-gray-500 dark:text-gray-400 mt-2">
        Вы уже воздержались от голосования. Благодарим за участие.
      </div>
    );
  }

  return (
    <>
      <Tooltip label="Воздержаться — значит сознательно не голосовать «за» или «против», сохраняя участие в кворуме.">
        <Button
          variant="secondary"
          disabled={!isVotingOpen || isSubmitting}
          onClick={() => setConfirmOpen(true)}
          icon={<InfoIcon />}
        >
          Воздержаться
        </Button>
      </Tooltip>

      <ConfirmDialog
        open={confirmOpen}
        title="Подтверждение воздержания"
        description="Вы уверены, что хотите воздержаться от голосования? Это решение будет зафиксировано системой."
        confirmLabel="Подтвердить"
        cancelLabel="Отменить"
        onConfirm={handleAbstain}
        onCancel={() => setConfirmOpen(false)}
        loading={isSubmitting}
      />

      {isSubmitting && (
        <Loader label="Отправка вашего решения..." />
      )}

      {error && (
        <div className="text-sm text-red-600 dark:text-red-400 mt-2">
          {error}
        </div>
      )}
    </>
  );
};

export default AbstainVoteButton;
