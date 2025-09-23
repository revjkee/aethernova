import React, { useEffect, useState } from 'react';
import { getAgentVoteMetadata } from '@/services/agents/voteInspectionService';
import { Tooltip } from '@/shared/components/Tooltip';
import { TrustLevelBadge } from '@/shared/components/TrustLevelBadge';
import { ReasoningLink } from '@/shared/components/ReasoningLink';
import { AgentAvatar } from '@/shared/components/AgentAvatar';
import { Loader } from '@/shared/components/Loader';
import { useAuditLogger } from '@/shared/hooks/useAuditLogger';

type AgentVoteTagProps = {
  proposalId: string;
  agentId: string;
};

type AgentVoteMeta = {
  agentName: string;
  coreModule: string;
  decisionReason: string;
  confidence: number; // 0.0 to 1.0
  consensusLevel: 'isolated' | 'partial' | 'majority' | 'unanimous';
  agentIconUrl?: string;
  reasoningLink: string;
  trustTag: 'low' | 'moderate' | 'high' | 'system-core';
};

const consensusColorMap: Record<AgentVoteMeta['consensusLevel'], string> = {
  isolated: 'text-red-500',
  partial: 'text-yellow-500',
  majority: 'text-blue-600',
  unanimous: 'text-green-600'
};

const AgentVoteTag: React.FC<AgentVoteTagProps> = ({ proposalId, agentId }) => {
  const [metadata, setMetadata] = useState<AgentVoteMeta | null>(null);
  const [loading, setLoading] = useState(true);
  const logAudit = useAuditLogger();

  useEffect(() => {
    const loadMetadata = async () => {
      try {
        const result = await getAgentVoteMetadata(proposalId, agentId);
        setMetadata(result);

        logAudit({
          type: 'AGENT_VOTE_TAG_VIEWED',
          proposalId,
          agentId,
          trustLevel: result.trustTag,
          consensusLevel: result.consensusLevel,
          confidence: result.confidence
        });
      } catch (err) {
        console.error('Ошибка загрузки данных агента:', err);
      } finally {
        setLoading(false);
      }
    };

    loadMetadata();
  }, [proposalId, agentId]);

  if (loading || !metadata) {
    return <Loader label="Загрузка голоса AI-агента..." />;
  }

  return (
    <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-md border border-gray-300 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 text-sm">
      <AgentAvatar name={metadata.agentName} src={metadata.agentIconUrl} />

      <div className="flex flex-col">
        <span className="font-medium text-gray-800 dark:text-gray-200">{metadata.agentName}</span>
        <div className="flex items-center gap-2">
          <Tooltip label={`Ядро принятия решений: ${metadata.coreModule}`}>
            <span className="text-xs text-gray-500 dark:text-gray-400">
              {metadata.coreModule}
            </span>
          </Tooltip>

          <Tooltip label={`Доверие к агенту: ${metadata.trustTag}`}>
            <TrustLevelBadge level={metadata.trustTag} />
          </Tooltip>

          <Tooltip label={`Уровень согласия с другими агентами`}>
            <span className={`text-xs font-semibold ${consensusColorMap[metadata.consensusLevel]}`}>
              {metadata.consensusLevel}
            </span>
          </Tooltip>
        </div>

        <div className="mt-1 text-xs text-gray-600 dark:text-gray-400">
          Уверенность: {(metadata.confidence * 100).toFixed(1)}%
        </div>

        <div className="mt-1">
          <Tooltip label={metadata.decisionReason}>
            <span className="text-xs text-blue-600 dark:text-blue-400 cursor-help truncate max-w-[200px]">
              {metadata.decisionReason}
            </span>
          </Tooltip>
        </div>

        <div className="mt-1">
          <ReasoningLink href={metadata.reasoningLink} />
        </div>
      </div>
    </div>
  );
};

export default AgentVoteTag;
