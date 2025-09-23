import React, { useEffect, useState } from 'react';
import { useTheme } from '@/shared/hooks/useThemeSwitcher';
import { useSocket } from '@/shared/hooks/useSocket';
import { Spinner } from '@/shared/components/Spinner';
import { Alert } from '@/shared/components/Alert';
import { EthicsShieldIcon } from '@/shared/components/icons/EthicsShieldIcon';
import './styles/AgentEthicsCompliance.css';

interface EthicsComplianceData {
  timestamp: number;
  isCompliant: boolean;
  ethicsScore: number; // 0–100
  flagged: boolean;
  blocked: boolean;
  reason: string | null;
  sourcePolicy: string | null;
}

interface AgentEthicsComplianceProps {
  agentId: string;
}

export const AgentEthicsCompliance: React.FC<AgentEthicsComplianceProps> = ({ agentId }) => {
  const { theme } = useTheme();
  const [data, setData] = useState<EthicsComplianceData | null>(null);
  const [loading, setLoading] = useState(true);
  const { connect, disconnect } = useSocket(`/agents/${agentId}/ethics`);

  useEffect(() => {
    const socket = connect((event) => {
      const payload = JSON.parse(event.data) as EthicsComplianceData;
      setData(payload);
      setLoading(false);
    });

    return () => disconnect(socket);
  }, [agentId]);

  const getEthicsLevel = (score: number): string => {
    if (score >= 90) return 'Высший';
    if (score >= 75) return 'Нормативный';
    if (score >= 50) return 'Допустимый';
    return 'Низкий';
  };

  const getColorClass = (): string => {
    if (!data) return '';
    if (data.blocked) return 'ethics-blocked';
    if (data.flagged) return 'ethics-flagged';
    if (data.ethicsScore >= 90) return 'ethics-compliant-high';
    if (data.ethicsScore >= 75) return 'ethics-compliant-mid';
    return 'ethics-compliant-low';
  };

  return (
    <div className={`agent-ethics-compliance ${theme} ${getColorClass()}`}>
      <div className="header">
        <EthicsShieldIcon />
        <h3>Этическое соответствие</h3>
      </div>

      {loading || !data ? (
        <div className="loading">
          <Spinner />
          <span>Проверка этического соответствия...</span>
        </div>
      ) : (
        <>
          <div className="compliance-status">
            <div className="label">Статус:</div>
            <div className="value">
              {data.isCompliant ? 'Соответствует' : 'Нарушение'}
            </div>
            <div className="label">Оценка:</div>
            <div className="value">{data.ethicsScore}/100 ({getEthicsLevel(data.ethicsScore)})</div>
            {data.sourcePolicy && (
              <>
                <div className="label">Политика:</div>
                <div className="value">{data.sourcePolicy}</div>
              </>
            )}
            {data.reason && (
              <>
                <div className="label">Причина:</div>
                <div className="value reason">{data.reason}</div>
              </>
            )}
          </div>

          {data.blocked && (
            <Alert
              type="error"
              title="Заблокировано системой морали"
              message="Действие агента было остановлено из-за критического нарушения этики."
            />
          )}

          {!data.blocked && data.flagged && (
            <Alert
              type="warning"
              title="Замечание от AI Ethics Engine"
              message="Зафиксировано потенциальное отклонение от этической нормы."
            />
          )}
        </>
      )}
    </div>
  );
};
