// src/widgets/Governance/ProposalDetailsView.tsx

import React, { useEffect, useState } from 'react';
import styles from './ProposalDetailsView.module.css';
import { useParams } from 'react-router-dom';
import { fetchProposalById } from '@/services/governance';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { IntentGraph } from '@/widgets/Agents/AgentIntentGraph';
import { ZKProofTag } from '@/widgets/Agents/AgentZKVerifiedTag';
import { AnomalyBadge } from '@/widgets/Agents/AgentAnomalyBadge';
import { AgentAvatarCard } from '@/widgets/Agents/AgentAvatarCard';
import { Button } from '@/components/ui/button';
import { VotePanel } from '@/widgets/Governance/VotePanel';

export const ProposalDetailsView: React.FC = () => {
  const { proposalId } = useParams<{ proposalId: string }>();
  const [proposal, setProposal] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const load = async () => {
      try {
        const data = await fetchProposalById(proposalId);
        setProposal(data);
      } catch (e) {
        console.error('Proposal fetch failed', e);
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [proposalId]);

  if (loading) {
    return <Skeleton className={styles.skeletonContainer} />;
  }

  if (!proposal) {
    return <div className={styles.error}>Proposal not found</div>;
  }

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <h2 className={styles.title}>{proposal.title}</h2>
        <div className={styles.meta}>
          <Badge variant="info">#{proposal.id}</Badge>
          <Badge variant={proposal.status === 'active' ? 'success' : 'muted'}>
            {proposal.status}
          </Badge>
          <ZKProofTag verified={proposal.zkVerified} />
          {proposal.anomalyScore > 0.5 && <AnomalyBadge score={proposal.anomalyScore} />}
        </div>
      </div>

      <div className={styles.proposerBlock}>
        <AgentAvatarCard agentId={proposal.proposerId} />
        <span className={styles.timestamp}>
          Proposed on: {new Date(proposal.timestamp).toLocaleString()}
        </span>
      </div>

      <div className={styles.section}>
        <h3>Description</h3>
        <p className={styles.description}>{proposal.description}</p>
      </div>

      <div className={styles.section}>
        <h3>Intent Graph</h3>
        <IntentGraph intentTree={proposal.intentGraph} />
      </div>

      <div className={styles.section}>
        <h3>Reasoning Trace</h3>
        <pre className={styles.reasoning}>{proposal.reasoningTrace || 'N/A'}</pre>
      </div>

      <div className={styles.section}>
        <h3>Voting</h3>
        <VotePanel proposalId={proposal.id} currentStatus={proposal.status} />
      </div>

      {proposal.canOverride && (
        <div className={styles.overrideSection}>
          <Button variant="destructive" size="sm">
            Force Override
          </Button>
        </div>
      )}
    </div>
  );
};

export default ProposalDetailsView;
