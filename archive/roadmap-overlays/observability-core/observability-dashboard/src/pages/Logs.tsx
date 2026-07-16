import React, { useState } from 'react';
import LogSearch, { LogEntry } from '../components/LogSearch';
import { Calendar, FileText, AlertTriangle, XCircle } from 'lucide-react';
import { useTranslation } from 'react-i18next';

const Logs: React.FC = () => {
  const { t } = useTranslation();
  const [logs, setLogs] = useState<LogEntry[]>([]);

  const getLevelIcon = (level: LogEntry['level']) => {
    switch (level) {
      case 'error':
      case 'critical':
        return <XCircle className="h-4 w-4 text-red-500" />;
      case 'warning':
        return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
      default:
        return <FileText className="h-4 w-4 text-blue-500" />;
    }
  };

  const getLevelColor = (level: LogEntry['level']) => {
    switch (level) {
      case 'critical': return 'border-l-red-600 bg-red-50 dark:bg-red-900/20';
      case 'error': return 'border-l-red-500 bg-red-50 dark:bg-red-900/20';
      case 'warning': return 'border-l-yellow-500 bg-yellow-50 dark:bg-yellow-900/20';
      case 'info': return 'border-l-blue-500 bg-blue-50 dark:bg-blue-900/20';
      case 'debug': return 'border-l-gray-500 bg-gray-50 dark:bg-gray-800';
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
          {t('logs.title')}
        </h1>
        <div className="text-sm text-gray-500 dark:text-gray-400">
          {logs.length} {logs.length === 0 ? t('logs.noLogs') : 'logs found'}
        </div>
      </div>

      {/* Search Component */}
      <LogSearch onLogsUpdate={setLogs} />

      {/* Logs Display */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md border border-gray-200 dark:border-gray-700">
        <div className="p-4 border-b border-gray-200 dark:border-gray-700">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
            Log Entries
          </h3>
        </div>
        
        <div className="max-h-96 overflow-y-auto">
          {logs.length === 0 ? (
            <div className="p-8 text-center">
              <FileText className="h-12 w-12 text-gray-400 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
                No logs found
              </h3>
              <p className="text-gray-600 dark:text-gray-400">
                Adjust your search filters to find specific log entries.
              </p>
            </div>
          ) : (
            <div className="divide-y divide-gray-200 dark:divide-gray-700">
              {logs.slice(0, 50).map(log => (
                <div
                  key={log.id}
                  className={`p-4 border-l-4 ${getLevelColor(log.level)} hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors`}
                >
                  <div className="flex items-start space-x-3">
                    {getLevelIcon(log.level)}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between mb-1">
                        <div className="flex items-center space-x-2">
                          <span className="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                            {log.level}
                          </span>
                          <span className="text-xs text-gray-500 dark:text-gray-400">
                            {log.source}
                          </span>
                        </div>
                        <div className="flex items-center text-xs text-gray-500 dark:text-gray-400">
                          <Calendar className="h-3 w-3 mr-1" />
                          {new Date(log.timestamp).toLocaleString()}
                        </div>
                      </div>
                      
                      <p className="text-sm text-gray-900 dark:text-white mb-2">
                        {log.message}
                      </p>
                      
                      {log.metadata && Object.keys(log.metadata).length > 0 && (
                        <div className="text-xs text-gray-600 dark:text-gray-300">
                          <details>
                            <summary className="cursor-pointer hover:text-gray-800 dark:hover:text-gray-100">
                              Metadata
                            </summary>
                            <pre className="mt-2 p-2 bg-gray-100 dark:bg-gray-700 rounded text-xs overflow-x-auto">
                              {JSON.stringify(log.metadata, null, 2)}
                            </pre>
                          </details>
                        </div>
                      )}
                      
                      {log.tags && log.tags.length > 0 && (
                        <div className="flex flex-wrap gap-1 mt-2">
                          {log.tags.map(tag => (
                            <span
                              key={tag}
                              className="px-2 py-1 bg-gray-200 dark:bg-gray-600 text-gray-700 dark:text-gray-300 text-xs rounded"
                            >
                              {tag}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              ))}
              
              {logs.length > 50 && (
                <div className="p-4 text-center text-sm text-gray-500 dark:text-gray-400 bg-gray-50 dark:bg-gray-700">
                  Showing first 50 entries of {logs.length} total logs
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Logs;