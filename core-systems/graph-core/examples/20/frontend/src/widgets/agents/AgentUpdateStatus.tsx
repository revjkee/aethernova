import React, { useEffect, useState } from 'react';
import { useSocket } from '@/shared/hooks/useSocket';
import { StatusBadge } from '@/shared/components/StatusBadge';
import { Tooltip } from '@/shared/components/Tooltip';
import { VersionTag } from '@/shared/components/VersionTag';
import { ProgressBar } from '@/shared/components/ProgressBar';
import { ErrorIcon, SuccessIcon, PendingIcon } from '@/shared/components/icons';
import './styles/AgentUpdateStatus.css';

interface AgentUpdateStatusProps {
  agentId: string;
}

type UpdateStage =
  | 'idle'
  | 'downloading'
  | 'installing'
  | 'verifying'
  | 'completed'
  | 'failed'
  | 'rollback';

interface UpdateMeta {
  stage: UpdateStage;
  progress: number;
  currentVersion: string;
  targetVersion?: string;
  errorMessage?: string;
  timestamp: number;
  triggeredBy: string;
}

export const AgentUpdateStatus: React.FC<AgentUpdateStatusProps> = ({ agentId }) => {
  const [meta, setMeta] = useState<UpdateMeta>({
    stage: 'idle',
    progress: 0,
    currentVersion: 'v1.0.0',
    timestamp: Date.now(),
    triggeredBy: 'system',
  });

  const { connect, disconnect } = useSocket(`/agents/${agentId}/update_status`);

  useEffect(() => {
    const socket = connect((event) => {
      const data: UpdateMeta = JSON.parse(event.data);
      setMeta(data);
    });
    return () => disconnect(socket);
  }, [agentId]);

  const getStageLabel = (stage: UpdateStage) => {
    switch (stage) {
      case 'idle': return 'Ожидание обновлений';
      case 'downloading': return 'Загрузка пакета';
      case 'installing': return 'Установка обновления';
      case 'verifying': return 'Проверка целостности';
      case 'completed': return 'Обновление завершено';
      case 'failed': return 'Ошибка обновления';
      case 'rollback': return 'Откат версии';
    }
  };

  const getStageIcon = () => {
    switch (meta.stage) {
      case 'completed': return <SuccessIcon />;
      case 'failed': return <ErrorIcon />;
      default: return <PendingIcon />;
    }
  };

  const tooltip = (
    <div className="update-tooltip">
      <div><strong>Текущая версия:</strong> {meta.currentVersion}</div>
      {meta.targetVersion && <div><strong>Целевая версия:</strong> {meta.targetVersion}</div>}
      <div><strong>Стадия:</strong> {getStageLabel(meta.stage)}</div>
      <div><strong>Инициатор:</strong> {meta.triggeredBy}</div>
      <div><strong>Последнее обновление:</strong> {new Date(meta.timestamp).toLocaleString()}</div>
      {meta.errorMessage && <div className="error-text"><strong>Ошибка:</strong> {meta.errorMessage}</div>}
    </div>
  );

  return (
    <Tooltip content={tooltip}>
      <div className="agent-update-status">
        <StatusBadge
          label={getStageLabel(meta.stage)}
          icon={getStageIcon()}
          color={
            meta.stage === 'failed' ? '#e53935' :
            meta.stage === 'completed' ? '#43a047' : '#2196f3'
          }
        />
        <VersionTag version={meta.currentVersion} />
        {meta.stage !== 'idle' && meta.stage !== 'completed' && (
          <ProgressBar percent={meta.progress} status={meta.stage === 'failed' ? 'error' : 'normal'} />
        )}
      </div>
    </Tooltip>
  );
};
