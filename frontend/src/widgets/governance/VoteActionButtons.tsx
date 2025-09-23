import React, { useState, useCallback } from 'react';
import { Button } from '@/components/ui/button';
import { ShieldCheck, HandThumbsUp, HandThumbsDown, Ban, Loader2 } from 'lucide-react';
import styles from './styles/VoteActionButtons.module.css';
import classNames from 'classnames';
import { sendVote } from '@/services/governance/voteService';
import { useUserContext } from '@/context/UserContext';
import { useToast } from '@/components/ui/use-toast';
import { useGovernancePolicy } from '@/hooks/useGovernancePolicy';

interface VoteActionButtonsProps {
  proposalId: string;
  disabled?: boolean;
}

type VoteType = 'yes' | 'no' | 'abstain' | 'veto';

const voteLabels: Record<VoteType, string> = {
  yes: 'Голосовать ЗА',
  no: 'Голосовать ПРОТИВ',
  abstain: 'Воздержаться',
  veto: 'Наложить ВЕТО'
};

const voteIcons: Record<VoteType, JSX.Element> = {
  yes: <HandThumbsUp size={16} />,
  no: <HandThumbsDown size={16} />,
  abstain: <ShieldCheck size={16} />,
  veto: <Ban size={16} />
};

export const VoteActionButtons: React.FC<VoteActionButtonsProps> = ({
  proposalId,
  disabled = false
}) => {
  const { user } = useUserContext();
  const { hasVoted, canVote } = useGovernancePolicy(user?.id, proposalId);
  const { toast } = useToast();
  const [loadingVote, setLoadingVote] = useState<VoteType | null>(null);

  const handleVote = useCallback(async (vote: VoteType) => {
    if (disabled || hasVoted || !canVote) return;
    setLoadingVote(vote);
    try {
      await sendVote(proposalId, vote);
      toast({
        title: 'Голос учтён',
        description: `Вы проголосовали: ${voteLabels[vote]}`,
        duration: 4000
      });
    } catch (err: any) {
      toast({
        variant: 'destructive',
        title: 'Ошибка голосования',
        description: err.message || 'Попробуйте позже'
      });
    } finally {
      setLoadingVote(null);
    }
  }, [disabled, hasVoted, canVote, proposalId]);

  return (
    <div className={styles.votePanel}>
      {(Object.keys(voteLabels) as VoteType[]).map((voteType) => (
        <Button
          key={voteType}
          variant="outline"
          className={classNames(
            styles.voteButton,
            styles[`vote_${voteType}`],
            {
              [styles.disabled]: disabled || hasVoted || !canVote,
              [styles.loading]: loadingVote === voteType
            }
          )}
          onClick={() => handleVote(voteType)}
          disabled={disabled || hasVoted || !canVote || loadingVote !== null}
        >
          {loadingVote === voteType ? <Loader2 className="animate-spin" size={16} /> : voteIcons[voteType]}
          <span>{voteLabels[voteType]}</span>
        </Button>
      ))}
    </div>
  );
};

export default VoteActionButtons;
