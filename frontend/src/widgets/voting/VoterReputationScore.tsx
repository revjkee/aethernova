import React, { useEffect, useState, useMemo } from 'react';
import { fetchReputationFactors } from '@/services/governance/reputationEngine';
import { useZKIdentity } from '@/shared/hooks/useZKIdentity';
import { useAuditLogger } from '@/shared/hooks/useAuditLogger';
import { ReputationRadarChart } from '@/shared/components/ReputationRadarChart';
import { ReputationLevelBadge } from '@/shared/components/ReputationLevelBadge';
import { Loader } from '@/shared/components/Loader';
import { Tooltip } from '@/shared/components/Tooltip';
import { formatPercent } from '@/utils/formatters';
import { getTimeAgo } from '@/utils/timeUtils';

type VoterReputationScoreProps = {
  userAddress: string;
};

type ReputationData = {
  totalScore: number;
  scoreLevel: 'Low' | 'Medium' | 'High' | 'Elite';
  lastUpdated: string;
  zkVerified: boolean;
  components: {
    consistency: number;
    participation: number;
    impact: number;
    endorsement: number;
    alignment: number;
  };
};

const VoterReputationScore: React.FC<VoterReputationScoreProps> = ({ userAddress }) => {
  const [reputation, setReputation] = useState<ReputationData | null>(null);
  const [loading, setLoading] = useState(true);

  const { identityHash, zkProof } = useZKIdentity(userAddress);
  const logAudit = useAuditLogger();

  useEffect(() => {
    const loadReputation = async () => {
      try {
        setLoading(true);
        const rep = await fetchReputationFactors(userAddress);
        setReputation(rep);

        logAudit({
          type: 'REPUTATION_VIEWED',
          user: userAddress,
          identityHash,
          zkVerified: rep.zkVerified,
          totalScore: rep.totalScore,
          scoreLevel: rep.scoreLevel,
        });
      } catch (err) {
        console.error('Ошибка при получении репутации:', err);
        logAudit({
          type: 'REPUTATION_VIEW_ERROR',
          user: userAddress,
          error: err.message
        });
      } finally {
        setLoading(false);
      }
    };

    loadReputation();
  }, [userAddress]);

  const levelColor = useMemo(() => {
    switch (reputation?.scoreLevel) {
      case 'Elite': return 'bg-purple-600';
      case 'High': return 'bg-green-600';
      case 'Medium': return 'bg-yellow-500';
      case 'Low': return 'bg-red-600';
      default: return 'bg-gray-400';
    }
  }, [reputation]);

  if (loading || !reputation) {
    return <Loader label="Анализ репутации голосующего..." />;
  }

  return (
    <div className="bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-lg p-5 shadow-sm">
      <h3 className="text-lg font-bold text-gray-900 dark:text-white mb-4">
        Репутация голосующего
      </h3>

      <div className="flex items-center gap-4 mb-3">
        <ReputationLevelBadge level={reputation.scoreLevel} />
        <div className="text-sm text-gray-700 dark:text-gray-300">
          Общий балл: <strong>{reputation.totalScore.toFixed(2)}</strong><br />
          Обновлено: {getTimeAgo(reputation.lastUpdated)}<br />
          Подтверждено ZK: {reputation.zkVerified ? 'да' : 'нет'}
        </div>
      </div>

      <ReputationRadarChart
        data={{
          Consistency: reputation.components.consistency,
          Participation: reputation.components.participation,
          Impact: reputation.components.impact,
          Endorsement: reputation.components.endorsement,
          Alignment: reputation.components.alignment
        }}
      />

      <div className="grid grid-cols-2 gap-4 mt-5 text-sm text-gray-600 dark:text-gray-400">
        <Tooltip label="Насколько последовательно пользователь голосует в соответствии со своими прошлыми решениями.">
          <div>📈 Последовательность: {formatPercent(reputation.components.consistency)}</div>
        </Tooltip>
        <Tooltip label="Доля предложений, в которых участвовал пользователь.">
          <div>📊 Активность: {formatPercent(reputation.components.participation)}</div>
        </Tooltip>
        <Tooltip label="Насколько его голос изменял итог распределения (вес/решающий вклад).">
          <div>⚖️ Влияние: {formatPercent(reputation.components.impact)}</div>
        </Tooltip>
        <Tooltip label="Уровень доверия со стороны других участников (делегирование, голоса поддержки).">
          <div>🤝 Одобрение: {formatPercent(reputation.components.endorsement)}</div>
        </Tooltip>
        <Tooltip label="Насколько пользователь голосует в соответствии с миссией DAO.">
          <div>🧭 Выравнивание: {formatPercent(reputation.components.alignment)}</div>
        </Tooltip>
      </div>
    </div>
  );
};

export default VoterReputationScore;
