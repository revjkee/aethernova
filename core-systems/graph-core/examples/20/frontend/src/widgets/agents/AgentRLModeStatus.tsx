import React, { useEffect, useState } from 'react';
import { useTheme } from '@/shared/hooks/useThemeSwitcher';
import { useSocket } from '@/shared/hooks/useSocket';
import { Tooltip } from '@/shared/components/Tooltip';
import { SimulationIcon } from '@/shared/components/icons/SimulationIcon';
import { Spinner } from '@/shared/components/Spinner';
import './styles/AgentRLModeStatus.css';

type RLMode =
  | 'live'
  | 'rl-train'
  | 'rl-eval'
  | 'sim-dry'
  | 'sim-override';

interface RLModePayload {
  mode: RLMode;
  sessionId?: string;
  since: number;
  source: string;
}

interface AgentRLModeStatusProps {
  agentId: string;
}

const MODE_LABELS: Record<RLMode, string> = {
  live: 'Live (боевой)',
  'rl-train': 'Обучение RL',
  'rl-eval': 'Оценка RL',
  'sim-dry': 'Сухая симуляция',
  'sim-override': 'Симуляция с вмешательством',
};

const MODE_CLASSES: Record<RLMode, string> = {
  live: 'mode-live',
  'rl-train': 'mode-train',
  'rl-eval': 'mode-eval',
  'sim-dry': 'mode-sim-dry',
  'sim-override': 'mode-sim-override',
};

export const AgentRLModeStatus: React.FC<AgentRLModeStatusProps> = ({ agentId }) => {
  const { theme } = useTheme();
  const [data, setData] = useState<RLModePayload | null>(null);
  const [loading, setLoading] = useState(true);
  const { connect, disconnect } = useSocket(`/agents/${agentId}/rl_mode`);

  useEffect(() => {
    const socket = connect((event) => {
      const payload = JSON.parse(event.data) as RLModePayload;
      setData(payload);
      setLoading(false);
    });
    return () => disconnect(socket);
  }, [agentId]);

  const renderContent = () => {
    if (loading || !data) {
      return (
        <div className="loading">
          <Spinner size="small" />
          <span>Загрузка статуса режима...</span>
        </div>
      );
    }

    const className = `agent-rlmode-status ${MODE_CLASSES[data.mode]} ${theme}`;
    const label = MODE_LABELS[data.mode];
    const since = new Date(data.since).toLocaleString('ru-RU');

    return (
      <Tooltip
        content={
          <div className="tooltip-content">
            <div><strong>Режим:</strong> {label}</div>
            <div><strong>Сессия:</strong> {data.sessionId || 'N/A'}</div>
            <div><strong>Источник:</strong> {data.source}</div>
            <div><strong>Активен с:</strong> {since}</div>
          </div>
        }
      >
        <div className={className}>
          <SimulationIcon mode={data.mode} />
          <span className="mode-label">{label}</span>
        </div>
      </Tooltip>
    );
  };

  return (
    <div className="agent-rlmode-wrapper">
      {renderContent()}
    </div>
  );
};
