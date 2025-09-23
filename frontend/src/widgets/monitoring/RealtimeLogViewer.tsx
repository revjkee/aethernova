import React, { useEffect, useRef, useState } from 'react';
import { motion } from 'framer-motion';
import { useTranslation } from 'react-i18next';
import { useRBAC } from '@/shared/hooks/useRBAC';
import { Alert } from '@/shared/components/Alert';
import { Spinner } from '@/shared/components/Spinner';
import { LogLine } from '@/shared/components/LogLine';
import { SearchBar } from '@/shared/components/SearchBar';
import { LevelSelector } from '@/shared/components/LevelSelector';
import { useWebSocket } from '@/shared/hooks/useWebSocket';
import clsx from 'clsx';

type LogLevel = 'DEBUG' | 'INFO' | 'WARN' | 'ERROR' | 'CRITICAL';

interface LogEntry {
  id: string;
  timestamp: string;
  level: LogLevel;
  message: string;
  context?: string;
  source?: string;
  traceId?: string;
}

const MAX_LOG_LINES = 5000;

export const RealtimeLogViewer: React.FC = () => {
  const { t } = useTranslation();
  const { hasPermission } = useRBAC();
  const [logBuffer, setLogBuffer] = useState<LogEntry[]>([]);
  const [search, setSearch] = useState('');
  const [levelFilter, setLevelFilter] = useState<LogLevel | 'ALL'>('ALL');
  const [error, setError] = useState<string | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);

  const canView = hasPermission('monitoring.logs.view');

  const { connect, disconnect, messages, isConnected } = useWebSocket<LogEntry>({
    url: '/ws/logs',
    reconnectInterval: 5000,
    onError: () => setError(t('monitoring.logs.error_connection')),
  });

  useEffect(() => {
    if (canView) connect();
    return () => disconnect();
  }, [canView]);

  useEffect(() => {
    if (!messages.length) return;

    setLogBuffer(prev => {
      const updated = [...prev, ...messages].slice(-MAX_LOG_LINES);
      return updated;
    });

    // Scroll to bottom when new log comes
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const filteredLogs = logBuffer.filter(log => {
    const matchesLevel = levelFilter === 'ALL' || log.level === levelFilter;
    const matchesSearch =
      !search ||
      log.message.toLowerCase().includes(search.toLowerCase()) ||
      (log.context?.toLowerCase().includes(search.toLowerCase()) ?? false) ||
      (log.source?.toLowerCase().includes(search.toLowerCase()) ?? false);
    return matchesLevel && matchesSearch;
  });

  if (!canView) return null;

  return (
    <motion.div
      className="h-[720px] w-full bg-black text-white rounded-md border border-gray-800 flex flex-col"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
    >
      <div className="p-4 flex justify-between items-center border-b border-gray-700 bg-gray-900">
        <div className="text-lg font-bold">{t('monitoring.logs.title')}</div>
        <div className="flex gap-4">
          <SearchBar placeholder={t('monitoring.logs.search')} value={search} onChange={setSearch} />
          <LevelSelector selected={levelFilter} onChange={setLevelFilter} />
        </div>
      </div>

      {error && <Alert type="error" message={error} />}

      {!isConnected && <Spinner label={t('monitoring.logs.connecting')} />}

      <div className="flex-1 overflow-y-auto font-mono text-sm p-2 bg-black">
        {filteredLogs.map(log => (
          <LogLine key={log.id} entry={log} />
        ))}
        <div ref={bottomRef} />
      </div>
    </motion.div>
  );
};

export default RealtimeLogViewer;
