// Sentinel Log Stream Component

import React, { useEffect, useRef } from 'react';
import { SentinelLog } from '../sentinelAPI';

interface SentinelLogStreamProps {
  logs: SentinelLog[];
}

export const SentinelLogStream: React.FC<SentinelLogStreamProps> = ({ logs }) => {
  const logContainerRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom when new logs arrive
  useEffect(() => {
    if (logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [logs]);

  const getLevelIcon = (level: SentinelLog['level']) => {
    switch (level) {
      case 'INFO':
        return <div className="w-2 h-2 bg-blue-500 rounded-full" />;
      case 'WARN':
        return <div className="w-2 h-2 bg-yellow-500 rounded-full" />;
      case 'ERROR':
        return <div className="w-2 h-2 bg-orange-500 rounded-full" />;
      case 'CRITICAL':
        return <div className="w-2 h-2 bg-red-500 rounded-full animate-pulse" />;
      default:
        return <div className="w-2 h-2 bg-gray-500 rounded-full" />;
    }
  };

  const getLevelColor = (level: SentinelLog['level']) => {
    switch (level) {
      case 'INFO':
        return 'text-blue-600 bg-blue-50 dark:bg-blue-900/20';
      case 'WARN':
        return 'text-yellow-600 bg-yellow-50 dark:bg-yellow-900/20';
      case 'ERROR':
        return 'text-orange-600 bg-orange-50 dark:bg-orange-900/20';
      case 'CRITICAL':
        return 'text-red-600 bg-red-50 dark:bg-red-900/20';
      default:
        return 'text-gray-600 bg-gray-50 dark:bg-gray-900/20';
    }
  };

  const formatTime = (timestamp: string) => {
    return new Date(timestamp).toLocaleTimeString('ru-RU', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  };

  return (
    <div className="bg-white dark:bg-zinc-900 rounded-lg shadow-sm border border-gray-200 dark:border-zinc-700">
      {/* Header */}
      <div className="px-4 py-3 border-b border-gray-200 dark:border-zinc-700 flex items-center justify-between">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
          Live журнал событий
        </h3>
        <div className="flex items-center space-x-2">
          <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
          <span className="text-sm text-gray-500 dark:text-gray-400">В реальном времени</span>
        </div>
      </div>

      {/* Log Stream */}
      <div 
        ref={logContainerRef}
        className="h-64 overflow-y-auto p-2 space-y-1 font-mono text-sm"
      >
        {logs.length === 0 ? (
          <div className="flex items-center justify-center h-full text-gray-500 dark:text-gray-400">
            Ожидание событий...
          </div>
        ) : (
          logs.map((log) => (
            <div 
              key={log.id}
              className={`flex items-start space-x-3 p-2 rounded ${getLevelColor(log.level)} hover:opacity-80 transition-opacity`}
            >
              {/* Timestamp */}
              <span className="text-gray-500 dark:text-gray-400 text-xs whitespace-nowrap">
                {formatTime(log.timestamp)}
              </span>

              {/* Level indicator */}
              <div className="flex items-center mt-1">
                {getLevelIcon(log.level)}
              </div>

              {/* Level badge */}
              <span className="text-xs font-medium px-2 py-0.5 rounded uppercase whitespace-nowrap">
                {log.level}
              </span>

              {/* Message */}
              <div className="flex-1 min-w-0">
                <p className="text-gray-900 dark:text-white break-words">
                  {log.message}
                </p>
                
                {/* Source and Agent ID */}
                <div className="flex items-center space-x-4 mt-1 text-xs text-gray-500 dark:text-gray-400">
                  <span>Источник: {log.source}</span>
                  {log.agentId && (
                    <span>Агент: {log.agentId}</span>
                  )}
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Footer with stats */}
      <div className="px-4 py-2 border-t border-gray-200 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800">
        <div className="flex items-center justify-between text-sm text-gray-600 dark:text-gray-400">
          <span>Всего событий: {logs.length}</span>
          <div className="flex items-center space-x-4">
            <span className="flex items-center space-x-1">
              <div className="w-2 h-2 bg-red-500 rounded-full" />
              <span>Критических: {logs.filter(l => l.level === 'CRITICAL').length}</span>
            </span>
            <span className="flex items-center space-x-1">
              <div className="w-2 h-2 bg-orange-500 rounded-full" />
              <span>Ошибок: {logs.filter(l => l.level === 'ERROR').length}</span>
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};