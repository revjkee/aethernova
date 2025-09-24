import React, { useEffect, useState, useMemo } from 'react';
import { fetchBallotStats, fetchVotingTrustIndex, fetchLiveForecast } from '@/services/governance/ballotAnalytics';
import { useAuditLogger } from '@/shared/hooks/useAuditLogger';
import { VoteOutcomeChart } from '@/shared/components/VoteOutcomeChart';
import { DelegationImpactGraph } from '@/shared/components/DelegationImpactGraph';
import { ZKVerificationBanner } from '@/shared/components/ZKVerificationBanner';
import { TrustScoreBadge } from '@/shared/components/TrustScoreBadge';
import { Loader } from '@/shared/components/Loader';
import { formatDateTime } from '@/utils/timeUtils';
import { ProgressBar } from '@/shared/components/ProgressBar';
import { BallotSummary } from '@/types/governance';

type ProposalBallotSummaryProps = {
  proposalId: string;
};

const ProposalBallotSummary: React.FC<ProposalBallotSummaryProps> = ({ proposalId }) => {
  const [summary, setSummary] = useState<BallotSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [trustScore, setTrustScore] = useState<number | null>(null);
  const [forecast, setForecast] = useState<string | null>(null);

  const logAudit = useAuditLogger();

  useEffect(() => {
    const loadSummary = async () => {
      setLoading(true);
      try {
        const stats = await fetchBallotStats(proposalId);
        const trust = await fetchVotingTrustIndex(proposalId);
        const prediction = await fetchLiveForecast(proposalId);

        setSummary(stats);
        setTrustScore(trust);
        setForecast(prediction);

        logAudit({
          type: 'BALLOT_SUMMARY_VIEWED',
          proposalId,
          timestamp: new Date().toISOString()
        });
      } catch (err) {
        console.error('Failed to load proposal summary:', err);
        logAudit({
          type: 'BALLOT_SUMMARY_ERROR',
          proposalId,
          error: err.message
        });
      } finally {
        setLoading(false);
      }
    };

    loadSummary();
  }, [proposalId]);

  const totalWeight = useMemo(() => {
    if (!summary) return 0;
    return summary.options.reduce((acc, o) => acc + o.totalWeight, 0);
  }, [summary]);

  if (loading || !summary) {
    return <Loader label="Загрузка резюме голосования..." />;
  }

  return (
    <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg p-6 shadow-md">
      <h3 className="text-lg font-semibold text-gray-800 dark:text-white mb-4">
        Резюме голосования: {summary.title}
      </h3>

      <div className="mb-4 text-sm text-gray-600 dark:text-gray-300">
        Идентификатор предложения: <code>{proposalId}</code><br />
        Окончание голосования: {formatDateTime(summary.deadline)}<br />
        Прогноз от AI: <strong>{forecast}</strong>
      </div>

      <ZKVerificationBanner proposalId={proposalId} />

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-4">
        <div>
          <h4 className="text-md font-medium mb-2">Голоса и вес</h4>
          {summary.options.map((option, index) => (
            <div key={index} className="mb-3">
              <div className="flex justify-between text-sm mb-1">
                <span>{option.label}</span>
                <span>{option.totalWeight.toFixed(2)} токенов ({((option.totalWeight / totalWeight) * 100).toFixed(1)}%)</span>
              </div>
              <ProgressBar value={(option.totalWeight / totalWeight) * 100} />
            </div>
          ))}
        </div>

        <div>
          <h4 className="text-md font-medium mb-2">Индикаторы делегирования</h4>
          <DelegationImpactGraph data={summary.delegationImpact} />
        </div>
      </div>

      <div className="mt-6">
        <h4 className="text-md font-medium mb-2">Распределение голосов</h4>
        <VoteOutcomeChart options={summary.options} />
      </div>

      <div className="mt-6 flex justify-between items-center">
        <TrustScoreBadge score={trustScore ?? 0} />
        <div className="text-xs text-gray-500 dark:text-gray-400">
          Последнее обновление: {formatDateTime(summary.lastUpdated)}
        </div>
      </div>
    </div>
  );
};

export default ProposalBallotSummary;
