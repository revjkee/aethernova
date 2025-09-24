import React, { useEffect, useState } from 'react';
import { useSocket } from '@/shared/hooks/useSocket';
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import { Spinner } from '@/shared/components/Spinner';
import { useTheme } from '@/shared/hooks/useThemeSwitcher';
import { formatTimestamp } from '@/shared/utils/timeUtils';
import { BatteryIcon } from '@/shared/components/icons/BatteryIcon';
import './styles/AgentEnergyUsage.css';

interface EnergyDataPoint {
  timestamp: number;
  usage: number;        // в мВт
  baseline: number;     // базовая активность
}

interface AgentEnergyUsageProps {
  agentId: string;
}

export const AgentEnergyUsage: React.FC<AgentEnergyUsageProps> = ({ agentId }) => {
  const { theme } = useTheme();
  const [data, setData] = useState<EnergyDataPoint[]>([]);
  const [currentUsage, setCurrentUsage] = useState<number>(0);
  const [baseline, setBaseline] = useState<number>(0);
  const [loading, setLoading] = useState(true);
  const { connect, disconnect } = useSocket(`/agents/${agentId}/energy`);

  useEffect(() => {
    let mounted = true;
    const socket = connect((event) => {
      const payload = JSON.parse(event.data) as EnergyDataPoint;
      if (!mounted) return;

      setCurrentUsage(payload.usage);
      setBaseline(payload.baseline);
      setData((prev) => [...prev.slice(-49), payload]);
      setLoading(false);
    });

    return () => {
      mounted = false;
      disconnect(socket);
    };
  }, [agentId]);

  const energyLevelLabel = (): string => {
    if (currentUsage < baseline * 0.75) return 'Экономичный режим';
    if (currentUsage <= baseline * 1.25) return 'Нормальная нагрузка';
    return 'Высокая нагрузка';
  };

  return (
    <div className={`agent-energy-usage ${theme}`}>
      <div className="header">
        <h3>Потребление энергии</h3>
        <BatteryIcon usage={currentUsage} baseline={baseline} />
      </div>

      {loading ? (
        <div className="loading">
          <Spinner />
          <span>Сбор данных...</span>
        </div>
      ) : (
        <>
          <div className="stats">
            <div className="metric">
              <span className="label">Текущая нагрузка:</span>
              <span className="value">{currentUsage.toFixed(1)} мВт</span>
            </div>
            <div className="metric">
              <span className="label">Базовый уровень:</span>
              <span className="value">{baseline.toFixed(1)} мВт</span>
            </div>
            <div className={`metric status ${currentUsage > baseline * 1.25 ? 'high' : currentUsage < baseline * 0.75 ? 'low' : 'normal'}`}>
              <span className="label">Статус:</span>
              <span className="value">{energyLevelLabel()}</span>
            </div>
          </div>

          <div className="chart-container">
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={data}>
                <XAxis
                  dataKey="timestamp"
                  tickFormatter={(tick) => formatTimestamp(tick)}
                  minTickGap={20}
                />
                <YAxis unit=" мВт" />
                <Tooltip
                  labelFormatter={(label) => formatTimestamp(label as number)}
                  formatter={(val: number) => `${val.toFixed(1)} мВт`}
                />
                <Line type="monotone" dataKey="usage" stroke="#00e676" strokeWidth={2} dot={false} />
                <Line type="monotone" dataKey="baseline" stroke="#2979ff" strokeDasharray="3 3" dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </>
      )}
    </div>
  );
};
