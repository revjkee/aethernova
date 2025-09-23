import React, { useEffect, useState } from 'react';
import { useTheme } from '@/shared/hooks/useThemeSwitcher';
import { useSocket } from '@/shared/hooks/useSocket';
import { Spinner } from '@/shared/components/Spinner';
import { Alert } from '@/shared/components/Alert';
import { LatencyIcon } from '@/shared/components/icons/LatencyIcon';
import { ResponsiveContainer, LineChart, Line, XAxis, YAxis, Tooltip } from 'recharts';
import './styles/AgentDecisionLatency.css';

interface LatencyPoint {
  timestamp: number;
  latencyMs: number;
}

interface AgentDecisionLatencyProps {
  agentId: string;
  criticalThresholdMs?: number;
  warningThresholdMs?: number;
  maxPoints?: number;
}

export const AgentDecisionLatency: React.FC<AgentDecisionLatencyProps> = ({
  agentId,
  criticalThresholdMs = 1000,
  warningThresholdMs = 500,
  maxPoints = 60,
}) => {
  const { theme } = useTheme();
  const [latencyData, setLatencyData] = useState<LatencyPoint[]>([]);
  const [latest, setLatest] = useState<number | null>(null);
  const [maxLatency, setMaxLatency] = useState<number>(0);
  const [avgLatency, setAvgLatency] = useState<number>(0);
  const [loading, setLoading] = useState(true);
  const { connect, disconnect } = useSocket(`/agents/${agentId}/decision_latency`);

  useEffect(() => {
    const socket = connect((event) => {
      const point: LatencyPoint = JSON.parse(event.data);
      setLatencyData((prev) => {
        const next = [...prev.slice(-maxPoints + 1), point];
        const values = next.map((p) => p.latencyMs);
        setLatest(point.latencyMs);
        setMaxLatency(Math.max(...values));
        setAvgLatency(Math.round(values.reduce((a, b) => a + b, 0) / values.length));
        setLoading(false);
        return next;
      });
    });
    return () => disconnect(socket);
  }, [agentId, maxPoints]);

  const getLatencyStatus = () => {
    if (!latest) return 'neutral';
    if (latest > criticalThresholdMs) return 'critical';
    if (latest > warningThresholdMs) return 'warning';
    return 'ok';
  };

  const statusClass = `status-${getLatencyStatus()}`;

  return (
    <div className={`agent-decision-latency ${theme} ${statusClass}`}>
      <div className="header">
        <LatencyIcon />
        <h3>Задержка принятия решений</h3>
      </div>

      {loading ? (
        <div className="loading">
          <Spinner />
          <span>Загрузка данных...</span>
        </div>
      ) : (
        <>
          <div className="metrics">
            <div className="metric">
              <span className="label">Текущая:</span>
              <span className="value">{latest} мс</span>
            </div>
            <div className="metric">
              <span className="label">Средняя:</span>
              <span className="value">{avgLatency} мс</span>
            </div>
            <div className="metric">
              <span className="label">Максимум:</span>
              <span className="value">{maxLatency} мс</span>
            </div>
          </div>

          {(latest || 0) > criticalThresholdMs && (
            <Alert
              type="error"
              title="Критическая задержка"
              message="Превышен допустимый предел времени принятия решения"
            />
          )}

          {(latest || 0) > warningThresholdMs && latest! <= criticalThresholdMs && (
            <Alert
              type="warning"
              title="Замедление принятия решений"
              message="Обнаружено ухудшение времени ответа"
            />
          )}

          <div className="chart-container">
            <ResponsiveContainer width="100%" height={180}>
              <LineChart data={latencyData}>
                <XAxis
                  dataKey="timestamp"
                  tickFormatter={(ts) =>
                    new Date(ts).toLocaleTimeString('ru-RU', {
                      minute: '2-digit',
                      second: '2-digit',
                    })
                  }
                />
                <YAxis unit="мс" domain={['auto', 'auto']} />
                <Tooltip
                  labelFormatter={(ts) =>
                    new Date(ts as number).toLocaleTimeString('ru-RU')
                  }
                  formatter={(value) => [`${value} мс`, 'Latency']}
                />
                <Line
                  type="monotone"
                  dataKey="latencyMs"
                  stroke="#42a5f5"
                  strokeWidth={2}
                  dot={false}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </>
      )}
    </div>
  );
};
