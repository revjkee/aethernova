import React, { useEffect, useState, useMemo } from 'react';
import { fetchVoteImpactMetrics } from '@/services/governance/impactAnalysisService';
import { useAuditLogger } from '@/shared/hooks/useAuditLogger';
import { RadarChartWidget } from '@/shared/components/RadarChartWidget';
import { ImpactTagList } from '@/shared/components/ImpactTagList';
import { Loader } from '@/shared/components/Loader';
import { useZKIdentity } from '@/shared/hooks/useZKIdentity';
import { formatPercent } from '@/utils/formatters';
import { getTimeAgo } from '@/utils/timeUtils';

type VoteImpactRadarProps = {
  proposalId: string;
  userAddress: string;
};

type ImpactVector = {
  label: string;
  score: number; // 0–1
  description: string;
};

type ImpactData = {
  updatedAt: string;
  impactVectors: ImpactVector[];
  primaryImpacts: string[];
  longTermIndex: number;
  aiConfidence: number;
  zkVerified: boolean;
};

const VoteImpactRadar: React.FC<VoteImpactRadarProps> = ({ proposalId, userAddress }) => {
  const [impact, setImpact] = useState<ImpactData | null>(null);
  const [loading, setLoading] = useState(true);
  const { identityHash } = useZKIdentity(userAddress);
  const logAudit = useAuditLogger();

  useEffect(() => {
    const loadImpact = async () => {
      setLoading(true);
      try {
        const data = await fetchVoteImpactMetrics(proposalId);
        setImpact(data);

        logAudit({
          type: 'IMPACT_ANALYSIS_VIEWED',
          proposalId,
          user: userAddress,
          identityHash,
          zkVerified: data.zkVerified,
          aiConfidence: data.aiConfidence
        });
      } catch (err) {
        console.error('Ошибка загрузки анализа воздействия:', err);
        logAudit({
          type: 'IMPACT_ANALYSIS_ERROR',
          proposalId,
          user: userAddress,
          error: err.message
        });
      } finally {
        setLoading(false);
      }
    };

    loadImpact();
  }, [proposalId, userAddress]);

  const radarData = useMemo(() => {
    if (!impact) return [];
    return impact.impactVectors.map(v => ({
      label: v.label,
      value: parseFloat((v.score * 100).toFixed(2))
    }));
  }, [impact]);

  if (loading || !impact) {
    return <Loader label="Оценка системного воздействия..." />;
  }

  return (
    <div className="bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-xl p-6 shadow-sm">
      <h3 className="text-lg font-bold text-gray-800 dark:text-white mb-4">
        Системное воздействие голосования
      </h3>

      <div className="text-sm text-gray-600 dark:text-gray-400 mb-4">
        Обновлено: {getTimeAgo(impact.updatedAt)}<br />
        Долгосрочный индекс: {impact.longTermIndex.toFixed(2)}<br />
        AI уверенность в анализе: {formatPercent(impact.aiConfidence)}<br />
        ZK подтверждение: {impact.zkVerified ? 'да' : 'нет'}
      </div>

      <RadarChartWidget
        data={radarData}
        maxValue={100}
        labelFormat={(v) => `${v}%`}
        theme="governance"
      />

      <div className="mt-6">
        <h4 className="text-md font-semibold text-gray-700 dark:text-gray-300 mb-2">Основные векторы воздействия</h4>
        <ImpactTagList tags={impact.primaryImpacts} />
      </div>

      <div className="mt-5 grid grid-cols-1 sm:grid-cols-2 gap-4 text-sm text-gray-700 dark:text-gray-300">
        {impact.impactVectors.map((v, idx) => (
          <div key={idx} className="p-3 rounded-md border border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800">
            <div className="font-medium mb-1">{v.label}</div>
            <div>{v.description}</div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default VoteImpactRadar;
