import React, { useEffect, useState } from 'react';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip } from 'recharts';
import { Spinner } from '@/shared/components/Spinner';
import { useTheme } from '@/shared/hooks/useThemeSwitcher';
import { useSocket } from '@/shared/hooks/useSocket';
import { formatBytes } from '@/shared/utils/formatBytes';
import { Alert } from '@/shared/components/Alert';
import { MemoryIcon } from '@/shared/components/icons/MemoryIcon';
import './styles/AgentMemoryUsage.css';

interface MemorySnapshot {
  timestamp: number;
  used: number;       // bytes
  peak: number;       // bytes
  logs: number;       // bytes
  heap: number;       // bytes
}

interface AgentMemoryUsageProps {
  agentId: string;
}

export const AgentMemoryUsage: React.FC<AgentMemoryUsageProps> = ({ agentId }) => {
  const { theme } = useTheme();
  const [data, setData] = useState<MemorySnapshot[]>([]);
  const [current, setCurrent] = useState<MemorySnapshot | null>(null);
  const [loading, setLoading] = useState(true);
  const { connect, disconnect } = useSocket(`/agents/${agentId}/memory`);

  useEffect(() => {
    let mounted = true;
    const socket = connect((event) => {
      const payload = JSON.parse(event.data) as MemorySnapshot;
      if (!mounted) return;
      setCurrent(payload);
      setData((prev) => [...prev.slice(-59), payload]);
      setLoading(false);
    });

    return () => {
      mounted = false;
      disconnect(socket);
    };
  }, [agentId]);

  const isMemoryCritical = current ? current.used > current.peak * 0.95 : false;
  const isLogOverload = current ? current.logs > 512 * 1024 * 1024 : false; // 512MB

  return (
    <div className={`agent-memory-usage ${theme}`}>
      <div className="header">
        <h3>Использование памяти</h3>
        <MemoryIcon size={24} />
      </div>

      {loading || !current ? (
        <div className="loading">
          <Spinner />
          <span>Получение данных...</span>
        </div>
      ) : (
        <>
          <div className="metrics">
            <div className="metric">
              <span className="label">Текущая память:</span>
              <span className="value">{formatBytes(current.used)}</span>
            </div>
            <div className="metric">
              <span className="label">Пиковая нагрузка:</span>
              <span className="value">{formatBytes(current.peak)}</span>
            </div>
            <div className="metric">
              <span className="label">Heap:</span>
              <span className="value">{formatBytes(current.heap)}</span>
            </div>
            <div className="metric">
              <span className="label">Логи:</span>
              <span className="value">{formatBytes(current.logs)}</span>
            </div>
          </div>

          {(isMemoryCritical || isLogOverload) && (
            <Alert
              type="warning"
              title="Внимание: превышение лимитов"
              message={
                isMemoryCritical
                  ? 'Память близка к пиковому уровню'
                  : 'Объём логов превышает допустимый порог'
              }
            />
          )}

          <div className="chart-container">
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={data}>
                <XAxis
                  dataKey="timestamp"
                  tickFormatter={(ts) =>
                    new Date(ts).toLocaleTimeString('ru-RU', {
                      hour: '2-digit',
                      minute: '2-digit',
                      second: '2-digit',
                    })
                  }
                />
                <YAxis
                  tickFormatter={(v) => formatBytes(v)}
                  width={80}
                />
                <Tooltip
                  formatter={(v: number) => formatBytes(v)}
                  labelFormatter={(ts) =>
                    new Date(ts as number).toLocaleTimeString()
                  }
                />
                <Area
                  type="monotone"
                  dataKey="used"
                  stroke="#42a5f5"
                  fill="#42a5f5"
                  name="Used"
                />
                <Area
                  type="monotone"
                  dataKey="heap"
                  stroke="#7e57c2"
                  fill="#9575cd"
                  name="Heap"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </>
      )}
    </div>
  );
};
