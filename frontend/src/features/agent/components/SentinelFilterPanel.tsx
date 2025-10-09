// Sentinel Filter Panel Component

import React from 'react';

interface SentinelFilters {
  role: string;
  status: string;
  anomalyOnly: boolean;
  tactic: string;
}

interface SentinelFilterPanelProps {
  filters: SentinelFilters;
  onChange: (filters: SentinelFilters) => void;
}

export const SentinelFilterPanel: React.FC<SentinelFilterPanelProps> = ({ 
  filters, 
  onChange 
}) => {
  const handleFilterChange = (key: keyof SentinelFilters, value: any) => {
    onChange({
      ...filters,
      [key]: value
    });
  };

  const clearFilters = () => {
    onChange({
      role: 'all',
      status: 'all',
      anomalyOnly: false,
      tactic: 'all'
    });
  };

  return (
    <div className="bg-white dark:bg-zinc-900 rounded-lg shadow-sm border border-gray-200 dark:border-zinc-700 p-4">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
          Фильтры агентов
        </h3>
        <button
          onClick={clearFilters}
          className="text-sm text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300"
        >
          Сбросить все
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* Role Filter */}
        <div className="space-y-2">
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
            Роль агента
          </label>
          <select
            value={filters.role}
            onChange={(e) => handleFilterChange('role', e.target.value)}
            className="w-full px-3 py-2 border border-gray-300 dark:border-zinc-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 dark:bg-zinc-800 dark:text-white"
          >
            <option value="all">Все роли</option>
            <option value="monitor">Network Monitor</option>
            <option value="detection">Intrusion Detection</option>
            <option value="analysis">Behavioral Analysis</option>
            <option value="response">Incident Response</option>
            <option value="forensics">Digital Forensics</option>
          </select>
        </div>

        {/* Status Filter */}
        <div className="space-y-2">
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
            Статус
          </label>
          <select
            value={filters.status}
            onChange={(e) => handleFilterChange('status', e.target.value)}
            className="w-full px-3 py-2 border border-gray-300 dark:border-zinc-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 dark:bg-zinc-800 dark:text-white"
          >
            <option value="all">Все статусы</option>
            <option value="active">Активные</option>
            <option value="inactive">Неактивные</option>
            <option value="quarantined">В карантине</option>
            <option value="rogue">Изгои</option>
          </select>
        </div>

        {/* Tactic Filter */}
        <div className="space-y-2">
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
            Тактика MITRE ATT&CK
          </label>
          <select
            value={filters.tactic}
            onChange={(e) => handleFilterChange('tactic', e.target.value)}
            className="w-full px-3 py-2 border border-gray-300 dark:border-zinc-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 dark:bg-zinc-800 dark:text-white"
          >
            <option value="all">Все тактики</option>
            <option value="reconnaissance">Reconnaissance</option>
            <option value="initial-access">Initial Access</option>
            <option value="execution">Execution</option>
            <option value="persistence">Persistence</option>
            <option value="privilege-escalation">Privilege Escalation</option>
            <option value="defense-evasion">Defense Evasion</option>
            <option value="credential-access">Credential Access</option>
            <option value="discovery">Discovery</option>
            <option value="lateral-movement">Lateral Movement</option>
            <option value="collection">Collection</option>
            <option value="exfiltration">Exfiltration</option>
            <option value="impact">Impact</option>
          </select>
        </div>

        {/* Anomaly Toggle */}
        <div className="space-y-2">
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
            Фильтры аномалий
          </label>
          <div className="flex items-center space-x-2">
            <input
              type="checkbox"
              id="anomaly-only"
              checked={filters.anomalyOnly}
              onChange={(e) => handleFilterChange('anomalyOnly', e.target.checked)}
              className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
            />
            <label htmlFor="anomaly-only" className="text-sm text-gray-700 dark:text-gray-300">
              Только аномальные
            </label>
          </div>
          <div className="text-xs text-gray-500 dark:text-gray-400">
            Показать только агентов с высоким уровнем аномалий (&gt;50%)
          </div>
        </div>
      </div>

      {/* Active Filters Display */}
      {(filters.role !== 'all' || filters.status !== 'all' || filters.tactic !== 'all' || filters.anomalyOnly) && (
        <div className="mt-4 pt-4 border-t border-gray-200 dark:border-zinc-700">
          <div className="flex flex-wrap gap-2">
            <span className="text-sm text-gray-600 dark:text-gray-400">Активные фильтры:</span>
            
            {filters.role !== 'all' && (
              <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-200">
                Роль: {filters.role}
                <button
                  onClick={() => handleFilterChange('role', 'all')}
                  className="ml-1 text-blue-600 hover:text-blue-800 dark:text-blue-400"
                >
                  ×
                </button>
              </span>
            )}

            {filters.status !== 'all' && (
              <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-200">
                Статус: {filters.status}
                <button
                  onClick={() => handleFilterChange('status', 'all')}
                  className="ml-1 text-green-600 hover:text-green-800 dark:text-green-400"
                >
                  ×
                </button>
              </span>
            )}

            {filters.tactic !== 'all' && (
              <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-200">
                Тактика: {filters.tactic}
                <button
                  onClick={() => handleFilterChange('tactic', 'all')}
                  className="ml-1 text-purple-600 hover:text-purple-800 dark:text-purple-400"
                >
                  ×
                </button>
              </span>
            )}

            {filters.anomalyOnly && (
              <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-200">
                Только аномальные
                <button
                  onClick={() => handleFilterChange('anomalyOnly', false)}
                  className="ml-1 text-red-600 hover:text-red-800 dark:text-red-400"
                >
                  ×
                </button>
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
};