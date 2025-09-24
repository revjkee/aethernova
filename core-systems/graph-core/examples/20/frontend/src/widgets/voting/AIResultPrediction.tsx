import React, { useEffect, useState, useMemo } from 'react';
import { fetchLiveVotingData, fetchDelegationImpact } from '@/services/governance/ballotAnalytics';
import { runAIProjection } from '@/services/ai/aiForecastEngine';
import { useAuditLogger } from '@/shared/hooks/useAuditLogger';
import { useZKIdentity } from '@/shared/hooks/useZKIdentity';
import { Loader } from '@/shared/components/Loader';
import { PredictionChart } from '@/shared/components/PredictionChart';
import { ConfidenceBadge } from '@/shared/components/ConfidenceBadge';
import { VoteOutcomeIcon } from '@/shared/components/VoteOutcomeIcon';
import { getTimeUntilDeadline } from '@/utils/timeUtils';
import { formatPercent } from '@/utils/formatters';

type AIResultPredictionProps = {
  proposalId: string;
  userAddress: string;
};

type AIPredictionResult = {
  mostLikelyOutcome: string;
  probabilities: Record<string, number>;
  confidence: number;
  factors: {
    voterTurnout: number;
    delegatedWeight: number;
    voteAcceleration: number;
    zkVerified: boolean;
  };
  updatedAt: string;
};

const AIResultPrediction: React.FC<AIResultPredictionProps> = ({ proposalId, userAddress }) => {
  const [prediction, setPrediction] = useState<AIPredictionResult | null>(null);
  const [loading, setLoading] = useState(true);
  const logAudit = useAuditLogger();
  const { identityHash } = useZKIdentity(userAddress);

  useEffect(() => {
    const fetchAndPredict = async () => {
      setLoading(true);
      try {
        const votingData = await fetchLiveVotingData(proposalId);
        const delegationImpact = await fetchDelegationImpact(proposalId);

        const result = await runAIProjection({
          proposalId,
          liveVotes: votingData,
          delegationStats: delegationImpact,
        });

        setPrediction(result);

        logAudit({
          type: 'AI_PREDICTION_GENERATED',
          proposalId,
          user: userAddress,
          identityHash,
          timestamp: new Date().toISOString()
        });
      } catch (err) {
        console.error('AI prediction error:', err);
        logAudit({
          type: 'AI_PREDICTION_FAILED',
          proposalId,
          user: userAddress,
          error: err.message
        });
      } finally {
        setLoading(false);
      }
    };

    fetchAndPredict();
  }, [proposalId, userAddress]);

  if (loading || !prediction) {
    return <Loader label="AI анализ текущего голосования..." />;
  }

  return (
    <div className="bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-lg p-5 shadow-sm">
      <h3 className="text-lg font-semibold text-gray-800 dark:text-white mb-3">
        AI-прогноз результата голосования
      </h3>

      <div className="text-sm text-gray-600 dark:text-gray-400 mb-3">
        Обновлено: {new Date(prediction.updatedAt).toLocaleString()}<br />
        До завершения: <strong>{getTimeUntilDeadline(prediction.updatedAt)}</strong>
      </div>

      <div className="flex items-center gap-4 mb-4">
        <VoteOutcomeIcon option={prediction.mostLikelyOutcome} />
        <div className="text-md font-medium">
          Наиболее вероятный результат: <span className="text-blue-700 dark:text-blue-300">{prediction.mostLikelyOutcome}</span>
        </div>
        <ConfidenceBadge confidence={prediction.confidence} />
      </div>

      <PredictionChart probabilities={prediction.probabilities} />

      <div className="mt-6">
        <h4 className="text-md font-semibold text-gray-700 dark:text-gray-300 mb-2">Факторы прогноза</h4>
        <ul className="text-sm space-y-1 text-gray-600 dark:text-gray-400 list-disc ml-5">
          <li>Явка избирателей: {formatPercent(prediction.factors.voterTurnout)}</li>
          <li>Доля делегированного веса: {formatPercent(prediction.factors.delegatedWeight)}</li>
          <li>Ускорение тренда голосов: {prediction.factors.voteAcceleration.toFixed(2)}%</li>
          <li>ZK-доказательства подтверждены: {prediction.factors.zkVerified ? 'да' : 'нет'}</li>
        </ul>
      </div>
    </div>
  );
};

export default AIResultPrediction;
