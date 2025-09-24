import React, { useEffect, useState } from 'react';
import { Tooltip } from '@/shared/components/Tooltip';
import { StatusBadge } from '@/shared/components/StatusBadge';
import { ClockIcon, RestartIcon } from '@/shared/components/icons';
import { useUptimeSocket } from '@/shared/hooks/useUptimeSocket';
import { formatUptime } from '@/shared/utils/timeUtils';
import './styles/AgentUptimeClock.css';

interface AgentUptimeClockProps {
  agentId: string;
  status?: 'active' | 'idle' | 'restarting';
}

interface UptimeData {
  startTimestamp: number;
  lastRestart: number;
  isRestarting: boolean;
}

export const AgentUptimeClock: React.FC<AgentUptimeClockProps> = ({ agentId, status }) => {
  const [uptimeData, setUptimeData] = useState<UptimeData>({
    startTimestamp: Date.now() - 1000 * 60 * 60 * 24,
    lastRestart: Date.now() - 1000 * 60 * 5,
    isRestarting: false,
  });

  const { connect, disconnect } = useUptimeSocket(`/agents/${agentId}/uptime`);

  useEffect(() => {
    const socket = connect((event) => {
      const data: UptimeData = JSON.parse(event.data);
      setUptimeData(data);
    });
    return () => disconnect(socket);
  }, [agentId]);

  const [uptimeString, setUptimeString] = useState<string>(formatUptime(Date.now() - uptimeData.startTimestamp));

  useEffect(() => {
    const interval = setInterval(() => {
      setUptimeString(formatUptime(Date.now() - uptimeData.startTimestamp));
    }, 1000);
    return () => clearInterval(interval);
  }, [uptimeData.startTimestamp]);

  const tooltip = (
    <div className="uptime-tooltip">
      <div><strong>Аптайм:</strong> {uptimeString}</div>
      <div><strong>С момента перезапуска:</strong> {new Date(uptimeData.lastRestart).toLocaleString()}</div>
      <div><strong>Режим:</strong> {status || 'неизвестен'}</div>
    </div>
  );

  const icon = uptimeData.isRestarting ? <RestartIcon /> : <ClockIcon />;
  const color =
    uptimeData.isRestarting ? '#e53935' :
    status === 'idle' ? '#ffb300' :
    status === 'active' ? '#43a047' :
    '#90a4ae';

  return (
    <Tooltip content={tooltip}>
      <div className="agent-uptime-clock">
        <StatusBadge
          icon={icon}
          label={uptimeString}
          color={color}
        />
      </div>
    </Tooltip>
  );
};
