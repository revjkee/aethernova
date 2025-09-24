import React, { useEffect, useState } from 'react';
import { useTheme } from '@/shared/hooks/useThemeSwitcher';
import { useSocket } from '@/shared/hooks/useSocket';
import { Tooltip } from '@/shared/components/Tooltip';
import { AnomalyIcon } from '@/shared/components/icons/AnomalyIcon';
import { Spinner } from '@/shared/components/Spinner';
import './styles/AgentAnomalyBadge.css';

interface AnomalyData {
  id: string;
  timestamp: number;
  type: 'intent_conflict' | 'behavior_deviation' | 'security_breach' | 'performance_drop' | 'unknown';
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  sourceModule: string;
  resolved: boolean;
}

interface AgentAnomalyBadgeProps {
  agentId: string;
  showResolved?: boolean;
}

export const AgentAnomalyBadge: React.FC<AgentAnomalyBadgeProps> = ({
  agentId,
  showResolved = false,
}) => {
  const { theme } = useTheme();
  const [anomaly, setAnomaly] = useState<AnomalyData | null>(null);
  const [loading, setLoading] = useState(true);
  const { connect, disconnect } = useSocket(`/agents/${agentId}/anomaly`);

  useEffect(() => {
    const socket = connect((event) => {
      const data: AnomalyData = JSON.parse(event.data);
      if (!data.resolved || showResolved) {
        setAnomaly(data);
      } else {
        setAnomaly(null);
      }
      setLoading(false);
    });
    return () => disconnect(socket);
  }, [agentId, showResolved]);

  if (loading) {
    return (
      <div className="agent-anomaly-badge loading">
        <Spinner size="small" />
      </div>
    );
  }

  if (!anomaly) {
    return null;
  }

  const severityClass = `severity-${anomaly.severity}`;
  const timeLabel = new Date(anomaly.timestamp).toLocaleTimeString('ru-RU');

  return (
    <Tooltip
      content={
        <div className="anomaly-tooltip">
          <div><strong>Тип:</strong> {anomaly.type.replace('_', ' ')}</div>
          <div><strong>Сообщение:</strong> {anomaly.message}</div>
          <div><strong>Источник:</strong> {anomaly.sourceModule}</div>
          <div><strong>Время:</strong> {timeLabel}</div>
          <div><strong>Статус:</strong> {anomaly.resolved ? 'Устранено' : 'Активно'}</div>
        </div>
      }
    >
      <div className={`agent-anomaly-badge ${theme} ${severityClass}`}>
        <AnomalyIcon severity={anomaly.severity} />
        <span className="anomaly-type">{anomaly.type}</span>
      </div>
    </Tooltip>
  );
};
