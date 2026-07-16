import React, { useState, useEffect, useCallback } from 'react';
import { Search, Download, RefreshCw, AlertCircle } from 'lucide-react';

export interface LogEntry {
  id: string;
  timestamp: string;
  level: 'debug' | 'info' | 'warning' | 'error' | 'critical';
  message: string;
  source: string;
  metadata?: Record<string, any>;
  tags?: string[];
}

interface LogSearchProps {
  onLogsUpdate: (logs: LogEntry[]) => void;
  className?: string;
}

const LogSearch: React.FC<LogSearchProps> = ({ onLogsUpdate, className = '' }) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [filters, setFilters] = useState({
    level: 'all' as string,
    source: 'all' as string,
    dateRange: 'last24h' as string,
    tags: [] as string[],
  });
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Mock log data generator
  const generateMockLogs = useCallback((): LogEntry[] => {
    const levels: LogEntry['level'][] = ['debug', 'info', 'warning', 'error', 'critical'];
    const sources = ['agent-system', 'api-gateway', 'database', 'auth-service', 'monitoring'];
    const sampleMessages = [
      'Agent restart completed successfully',
      'High memory usage detected',
      'Authentication failed for user',
      'Database connection established',
      'API request processed',
      'System health check passed',
      'Configuration updated',
      'Error processing request',
      'Service started successfully',
      'Alert threshold exceeded'
    ];

    const logs: LogEntry[] = [];
    for (let i = 0; i < 100; i++) {
      const level = levels[Math.floor(Math.random() * levels.length)];
      const source = sources[Math.floor(Math.random() * sources.length)];
      const message = sampleMessages[Math.floor(Math.random() * sampleMessages.length)];
      
      logs.push({
        id: `log_${i}_${Date.now()}`,
        timestamp: new Date(Date.now() - Math.random() * 24 * 60 * 60 * 1000).toISOString(),
        level,
        source,
        message: `${message} - ${Math.floor(Math.random() * 1000)}`,
        metadata: {
          requestId: `req_${Math.random().toString(36).substr(2, 9)}`,
          userId: Math.random() > 0.5 ? `user_${Math.floor(Math.random() * 1000)}` : undefined,
        },
        tags: ['production', source.split('-')[0]],
      });
    }

    return logs.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  }, []);

  // Search and filter logs
  const searchLogs = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      // Simulate API call delay
      await new Promise(resolve => setTimeout(resolve, 500));

      let logs = generateMockLogs();

      // Apply search query
      if (searchQuery) {
        logs = logs.filter(log =>
          log.message.toLowerCase().includes(searchQuery.toLowerCase()) ||
          log.source.toLowerCase().includes(searchQuery.toLowerCase())
        );
      }

      // Apply level filter
      if (filters.level !== 'all') {
        logs = logs.filter(log => log.level === filters.level);
      }

      // Apply source filter
      if (filters.source !== 'all') {
        logs = logs.filter(log => log.source === filters.source);
      }

      // Apply date range filter
      const now = new Date();
      let startDate: Date;
      switch (filters.dateRange) {
        case 'last1h':
          startDate = new Date(now.getTime() - 60 * 60 * 1000);
          break;
        case 'last24h':
          startDate = new Date(now.getTime() - 24 * 60 * 60 * 1000);
          break;
        case 'last7d':
          startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
          break;
        default:
          startDate = new Date(0);
      }

      logs = logs.filter(log => new Date(log.timestamp) >= startDate);

      onLogsUpdate(logs);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to search logs');
    } finally {
      setIsLoading(false);
    }
  }, [searchQuery, filters, generateMockLogs, onLogsUpdate]);

  // Auto-search when filters change
  useEffect(() => {
    searchLogs();
  }, [searchLogs]);

  const exportLogs = () => {
    // Mock export functionality
    console.log('Exporting logs with filters:', { searchQuery, filters });
  };

  return (
    <div className={`bg-white dark:bg-gray-800 rounded-lg shadow-md border border-gray-200 dark:border-gray-700 ${className}`}>
      <div className="p-4 border-b border-gray-200 dark:border-gray-700">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          Log Search & Filter
        </h3>

        {/* Search Bar */}
        <div className="relative mb-4">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 h-4 w-4" />
          <input
            type="text"
            placeholder="Search logs..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400 focus:ring-2 focus:ring-primary-500 focus:border-transparent"
          />
        </div>

        {/* Filters */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {/* Level Filter */}
          <div>
            <label className="block text-xs font-medium text-gray-700 dark:text-gray-300 mb-1">
              Level
            </label>
            <select
              value={filters.level}
              onChange={(e) => setFilters(prev => ({ ...prev, level: e.target.value }))}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-primary-500"
            >
              <option value="all">All Levels</option>
              <option value="debug">Debug</option>
              <option value="info">Info</option>
              <option value="warning">Warning</option>
              <option value="error">Error</option>
              <option value="critical">Critical</option>
            </select>
          </div>

          {/* Source Filter */}
          <div>
            <label className="block text-xs font-medium text-gray-700 dark:text-gray-300 mb-1">
              Source
            </label>
            <select
              value={filters.source}
              onChange={(e) => setFilters(prev => ({ ...prev, source: e.target.value }))}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-primary-500"
            >
              <option value="all">All Sources</option>
              <option value="agent-system">Agent System</option>
              <option value="api-gateway">API Gateway</option>
              <option value="database">Database</option>
              <option value="auth-service">Auth Service</option>
              <option value="monitoring">Monitoring</option>
            </select>
          </div>

          {/* Date Range Filter */}
          <div>
            <label className="block text-xs font-medium text-gray-700 dark:text-gray-300 mb-1">
              Time Range
            </label>
            <select
              value={filters.dateRange}
              onChange={(e) => setFilters(prev => ({ ...prev, dateRange: e.target.value }))}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-primary-500"
            >
              <option value="last1h">Last Hour</option>
              <option value="last24h">Last 24 Hours</option>
              <option value="last7d">Last 7 Days</option>
              <option value="all">All Time</option>
            </select>
          </div>

          {/* Action Buttons */}
          <div className="flex items-end space-x-2">
            <button
              onClick={searchLogs}
              disabled={isLoading}
              className="px-4 py-2 bg-primary-600 hover:bg-primary-700 disabled:bg-primary-400 text-white text-sm font-medium rounded-md transition-colors flex items-center space-x-2"
            >
              <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
              <span>Refresh</span>
            </button>
            <button
              onClick={exportLogs}
              className="px-4 py-2 bg-gray-600 hover:bg-gray-700 text-white text-sm font-medium rounded-md transition-colors flex items-center space-x-2"
            >
              <Download className="h-4 w-4" />
              <span>Export</span>
            </button>
          </div>
        </div>

        {/* Error Display */}
        {error && (
          <div className="mt-4 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md flex items-center space-x-2">
            <AlertCircle className="h-4 w-4 text-red-500" />
            <span className="text-sm text-red-700 dark:text-red-400">{error}</span>
          </div>
        )}
      </div>
    </div>
  );
};

export default LogSearch;