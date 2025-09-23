// src/widgets/Voting/VotingPanel.tsx

import React, { useMemo, useCallback, useEffect, useState } from 'react';
import { useProposalContext } from '@/entities/governance/hooks/useProposalContext';
import { useVoteStatus } from '@/entities/governance/hooks/useVoteStatus';
import { useQuorumThreshold } from '@/entities/governance/hooks/useQuorumThreshold';
import { useStakeInfo } from '@/entities/wallet/hooks/useStakeInfo';
import { useCountdown } from '@/shared/lib/useCountdown';
import { useAiHints } from '@/entities/ai/hooks/useAiHints';
import { submitVote } from '@/entities/governance/api/vote';
import { Spinner } from '@/shared/ui/Spinner';
import { Button } from '@/shared/ui/Button';
import { VoteActionButtons } from '@/widgets/Governance/VoteActionButtons';
import { VoteResultChart } from '@/widgets/Governance/VoteResultChart';
import { QuorumStatusIndicator } from '@/widgets/Governance/QuorumStatusIndicator';
import { ProposalVotingCountdown } from '@/widgets/Governance/ProposalVotingCountdown';
import { VoterReputationIndicator } from '@/widgets/Governance/VoterReputationIndicator';
import { EthicsApprovalMeter } from '@/widgets/Governance/EthicsApprovalMeter';
import { WidgetLoader } from '@/widgets/Governance/WidgetLoader';
import { notifySuccess, notifyError } from '@/shared/lib/notifications';
import styles from './styles/VotingPanel.module.css';

export const VotingPanel: React.FC = () => {
  const { proposal, isLoading: isProposalLoading } = useProposalContext();
  const { voteStatus, isSubmitting, refetch: refetchVoteStatus } = useVoteStatus(proposal?.id);
  const { quorum, thresholdReached } = useQuorumThreshold(proposal?.id);
  const { stake, canVote } = useStakeInfo(proposal?.id);
  const countdown = useCountdown(proposal?.endTime);
  const { aiHint, fetchHint } = useAiHints(proposal?.id);

  const [selectedOption, setSelectedOption] = useState<string | null>(null);

  useEffect(() => {
    if (proposal?.id) {
      fetchHint();
    }
  }, [proposal?.id, fetchHint]);

  const handleVote = useCallback(async () => {
    if (!selectedOption || !proposal) return;

    try {
      await submitVote(proposal.id, selectedOption);
      notifySuccess('Голос успешно отправлен');
      refetchVoteStatus();
    } catch (e) {
      notifyError('Ошибка при голосовании');
    }
  }, [selectedOption, proposal, refetchVoteStatus]);

  const renderVoteControls = () => {
    if (!canVote) return <div className={styles.restricted}>Вы не можете голосовать по этой инициативе.</div>;

    return (
      <div className={styles.voteControls}>
        <VoteActionButtons
          selected={selectedOption}
          onSelect={setSelectedOption}
          disabled={isSubmitting}
        />
        <Button
          className={styles.submitButton}
          onClick={handleVote}
          disabled={!selectedOption || isSubmitting}
          loading={isSubmitting}
        >
          Подтвердить голос
        </Button>
      </div>
    );
  };

  if (isProposalLoading) return <Spinner />;

  return (
    <div className={styles.votingPanel}>
      <header className={styles.header}>
        <h2>{proposal?.title || 'Предложение'}</h2>
        <ProposalVotingCountdown endTime={proposal?.endTime} />
      </header>

      <section className={styles.status}>
        <QuorumStatusIndicator quorum={quorum} thresholdReached={thresholdReached} />
        <VoterReputationIndicator voterAddress={voteStatus?.voterAddress} />
        <EthicsApprovalMeter proposalId={proposal?.id} />
      </section>

      <section className={styles.chart}>
        <VoteResultChart results={proposal?.voteResults} />
      </section>

      <section className={styles.controls}>
        {renderVoteControls()}
      </section>

      {aiHint && (
        <section className={styles.aiHint}>
          <h4>AI Хинт:</h4>
          <p>{aiHint}</p>
        </section>
      )}

      <WidgetLoader proposalId={proposal?.id} position="panel-footer" />
    </div>
  );
};
