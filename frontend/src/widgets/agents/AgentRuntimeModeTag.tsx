import React, { useEffect, useState } from 'react';
import { useSocket } from '@/shared/hooks/useSocket';
import { Tooltip } from '@/shared/components/Tooltip';
import { Badge } from '@/shared/components/Badge';
import { ShieldIcon } from '@/shared/components/icons/ShieldIcon';
import './styles/AgentRuntimeModeTag.css';

interface AgentRuntimeModeTagProps {
  agentId: string;
}

type RuntimeMode = 'active' | 'idle' | 'sandboxed' | 'jailed' | 'emergency';

interface RuntimePayload {
  mode: RuntimeMode;
  timestamp: number;
  reason?: string;
  initiatedBy?: string;
}

const MODE_LABELS: Record<RuntimeMode, string> = {
  active: 'Активен',
  idle: 'Ожидание',
  sandboxed: 'Изоляция',
  jailed: 'Блокировка',
  emergency: 'Аварийный режим',
};

const MODE_COLORS: Record<RuntimeMode, string> = {
  active: '#4caf50',
  idle: '#9e9e9e',
  sandboxed: '#03a9f4',
  jailed: '#e53935',
  emergency: '#ff9800',
};

export const AgentRuntimeModeTag: React.FC<AgentRuntimeModeTagProps> = ({ agentId }) => {
  const [mode, setMode] = useState<RuntimeMode>('idle');
  const [meta, setMeta] = useState<{ timestamp: number; reason?: string; initiatedBy?: string }>({
    timestamp: Date.now(),
  });

  const { connect, disconnect } = useSocket(`/agents/${agentId}/runtime_mode`);

  useEffect(() => {
    const socket = connect((event) => {
      const payload: RuntimePayload = JSON.parse(event.data);
      setMode(payload.mode);
      setMeta({
        timestamp: payload.timestamp,
        reason: payload.reason,
        initiatedBy: payload.initiatedBy,
      });
    });

    return () => disconnect(socket);
  }, [agentId]);

  const tooltipContent = (
    <div className="runtime-tooltip">
      <div><strong>Режим:</strong> {MODE_LABELS[mode]}</div>
      <div><strong>Изменён:</strong> {new Date(meta.timestamp).toLocaleTimeString('ru-RU')}</div>
      {meta.initiatedBy && <div><strong>Источник:</strong> {meta.initiatedBy}</div>}
      {meta.reason && <div><strong>Причина:</strong> {meta.reason}</div>}
    </div>
  );

  return (
    <Tooltip content={tooltipContent}>
      <Badge
        text={MODE_LABELS[mode]}
        color={MODE_COLORS[mode]}
        icon={<ShieldIcon color={MODE_COLORS[mode]} size={16} />}
        className="runtime-mode-badge"
      />
    </Tooltip>
  );
};
