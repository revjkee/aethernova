import React, { useEffect, useRef, useState } from 'react';
import { useSocket } from '@/shared/hooks/useSocket';
import { useTheme } from '@/shared/hooks/useThemeSwitcher';
import { formatTimestamp } from '@/shared/utils/timeUtils';
import { LogIcon } from '@/shared/components/icons/LogIcon';
import './styles/AgentLogSnippet.css';

type LogLevel = 'info' | 'warn' | 'error' | 'decision' | 'action' | 'intent';

interface AgentLogEntry {
  timestamp: number;
  level: LogLevel;
  message: string;
  traceId?: string;
  sourceModule?: string;
}

interface AgentLogSnippetProps {
  agentId: string;
  maxLines?: number;
  autoScroll?: boolean;
  showTimestamps?: boolean;
}

export const AgentLogSnippet: React.FC<AgentLogSnippetProps> = ({
  agentId,
  maxLines = 100,
  autoScroll = true,
  showTimestamps = true,
}) => {
  const [logs, setLogs] = useState<AgentLogEntry[]>([]);
  const { theme } = useTheme();
  const containerRef = useRef<HTMLDivElement>(null);
  const { connect, disconnect } = useSocket(`/agents/${agentId}/logs`);

  useEffect(() => {
    const socket = connect((event) => {
      const log: AgentLogEntry = JSON.parse(event.data);
      setLogs((prev) => [...prev.slice(-maxLines + 1), log]);
    });

    return () => disconnect(socket);
  }, [agentId, maxLines]);

  useEffect(() => {
    if (autoScroll && containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [logs, autoScroll]);

  const levelClass = (level: LogLevel): string => {
    switch (level) {
      case 'info': return 'log-info';
      case 'warn': return 'log-warn';
      case 'error': return 'log-error';
      case 'decision': return 'log-decision';
      case 'action': return 'log-action';
      case 'intent': return 'log-intent';
      default: return '';
    }
  };

  return (
    <div className={`agent-log-snippet ${theme}`}>
      <div className="header">
        <LogIcon />
        <h3>Последние действия и логи</h3>
      </div>
      <div className="log-container" ref={containerRef}>
        {logs.length === 0 ? (
          <div className="log-placeholder">Логи отсутствуют</div>
        ) : (
          logs.map((log, idx) => (
            <div key={idx} className={`log-line ${levelClass(log.level)}`}>
              {showTimestamps && (
                <span className="log-timestamp">
                  {formatTimestamp(log.timestamp)}
                </span>
              )}
              {log.sourceModule && (
                <span className="log-source">[{log.sourceModule}]</span>
              )}
              <span className="log-message">{log.message}</span>
              {log.traceId && (
                <span className="log-trace-id">#{log.traceId}</span>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
};
