import React, { useEffect, useState } from 'react';
import { useSocket } from '@/shared/hooks/useSocket';
import { useTheme } from '@/shared/hooks/useThemeSwitcher';
import { Tooltip } from '@/shared/components/Tooltip';
import { Spinner } from '@/shared/components/Spinner';
import { ExecutionIcon } from '@/shared/components/icons/ExecutionIcon';
import './styles/AgentExecutionPreview.css';

type ExecutionState = 'scheduled' | 'awaiting-confirmation' | 'auto-executing';

interface ExecutionPreview {
  intentId: string;
  action: string;
  goal: string;
  justification: string;
  timestamp: number;
  source: string;
  confidence: number;
  state: ExecutionState;
}

interface AgentExecutionPreviewProps {
  agentId: string;
  showConfidence?: boolean;
  compact?: boolean;
}

export const AgentExecutionPreview: React.FC<AgentExecutionPreviewProps> = ({
  agentId,
  showConfidence = true,
  compact = false,
}) => {
  const { theme } = useTheme();
  const [preview, setPreview] = useState<ExecutionPreview | null>(null);
  const [loading, setLoading] = useState(true);
  const { connect, disconnect } = useSocket(`/agents/${agentId}/execution_preview`);

  useEffect(() => {
    const socket = connect((event) => {
      const data: ExecutionPreview = JSON.parse(event.data);
      setPreview(data);
      setLoading(false);
    });
    return () => disconnect(socket);
  }, [agentId]);

  if (loading || !preview) {
    return (
      <div className="agent-execution-preview loading">
        <Spinner size="small" />
      </div>
    );
  }

  const stateClass = `state-${preview.state}`;
  const time = new Date(preview.timestamp).toLocaleTimeString('ru-RU');

  return (
    <Tooltip
      content={
        <div className="execution-tooltip">
          <div><strong>Намерение:</strong> {preview.action}</div>
          <div><strong>Цель:</strong> {preview.goal}</div>
          <div><strong>Обоснование:</strong> {preview.justification}</div>
          <div><strong>Источник:</strong> {preview.source}</div>
          <div><strong>Состояние:</strong> {preview.state}</div>
          <div><strong>Ожидаемое время:</strong> {time}</div>
          {showConfidence && (
            <div><strong>Доверие:</strong> {Math.round(preview.confidence * 100)}%</div>
          )}
        </div>
      }
    >
      <div className={`agent-execution-preview ${theme} ${stateClass} ${compact ? 'compact' : ''}`}>
        <ExecutionIcon state={preview.state} />
        {!compact && (
          <div className="execution-content">
            <span className="action-label">{preview.action}</span>
            <span className="goal-label">{preview.goal}</span>
            {showConfidence && (
              <span className="confidence-label">
                {Math.round(preview.confidence * 100)}%
              </span>
            )}
          </div>
        )}
      </div>
    </Tooltip>
  );
};
