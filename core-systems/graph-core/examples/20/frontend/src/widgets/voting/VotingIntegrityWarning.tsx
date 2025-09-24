import React, { useEffect, useState } from 'react';
import { fetchVotingAnomalies } from '@/services/governance/integrityMonitor';
import { useAuditLogger } from '@/shared/hooks/useAuditLogger';
import { ThreatLevelBadge } from '@/shared/components/ThreatLevelBadge';
import { AlertBanner } from '@/shared/components/AlertBanner';
import { RiskFactorList } from '@/shared/components/RiskFactorList';
import { Loader } from '@/shared/components/Loader';
import { getTimeAgo } from '@/utils/timeUtils';

type VotingIntegrityWarningProps = {
  proposalId: string;
  userAddress: string;
};

type IntegrityAlert = {
  timestamp: string;
  threatLevel: 'low' | 'moderate' | 'high' | 'critical';
  zkVerified: boolean;
  anomalies: {
    type: string;
    severity: number; // 0.0 to 1.0
    description: string;
    mitigation: string;
  }[];
  aiConfidence: number;
};

const VotingIntegrityWarning: React.FC<VotingIntegrityWarningProps> = ({ proposalId, userAddress }) => {
  const [alert, setAlert] = useState<IntegrityAlert | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const logAudit = useAuditLogger();

  useEffect(() => {
    const checkIntegrity = async () => {
      setLoading(true);
      try {
        const result = await fetchVotingAnomalies(proposalId);
        setAlert(result);

        logAudit({
          type: 'VOTING_INTEGRITY_SCANNED',
          proposalId,
          user: userAddress,
          threatLevel: result.threatLevel,
          zkVerified: result.zkVerified,
          aiConfidence: result.aiConfidence,
        });
      } catch (err) {
        setError('Ошибка при анализе целостности голосования.');
        logAudit({
          type: 'VOTING_INTEGRITY_SCAN_ERROR',
          proposalId,
          user: userAddress,
          error: err.message,
        });
      } finally {
        setLoading(false);
      }
    };

    checkIntegrity();
  }, [proposalId, userAddress]);

  if (loading) {
    return <Loader label="Анализ целостности голосования..." />;
  }

  if (error) {
    return (
      <AlertBanner
        type="error"
        title="Ошибка целостности"
        message={error}
      />
    );
  }

  if (!alert || alert.anomalies.length === 0) {
    return null;
  }

  return (
    <div className="bg-white dark:bg-gray-900 border border-red-400 dark:border-red-600 rounded-lg p-5 shadow-sm">
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-md font-semibold text-red-800 dark:text-red-300">
          Обнаружены угрозы целостности голосования
        </h3>
        <ThreatLevelBadge level={alert.threatLevel} />
      </div>

      <div className="text-sm text-gray-600 dark:text-gray-400 mb-3">
        Последняя проверка: {getTimeAgo(alert.timestamp)}<br />
        Уверенность AI-анализа: {(alert.aiConfidence * 100).toFixed(1)}%<br />
        Подтверждено ZK: {alert.zkVerified ? 'да' : 'нет'}
      </div>

      <RiskFactorList
        factors={alert.anomalies.map(a => ({
          title: a.type,
          severity: a.severity,
          description: a.description,
          mitigation: a.mitigation
        }))}
      />
    </div>
  );
};

export default VotingIntegrityWarning;
