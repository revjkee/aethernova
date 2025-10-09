// Sentinel Agent Table Component

import React from 'react';
import { SentinelAgent } from '../sentinelAPI';

interface SentinelAgentTableProps {
  agents: SentinelAgent[];
  onSelect: (id: string) => void;
}

export const SentinelAgentTable: React.FC<SentinelAgentTableProps> = ({ 
  agents, 
  onSelect 
}) => {
  const getStatusColor = (status: SentinelAgent['status']) => {
    switch (status) {
      case 'ACTIVE': return 'text-green-600 bg-green-100';
      case 'INACTIVE': return 'text-gray-600 bg-gray-100';
      case 'QUARANTINED': return 'text-yellow-600 bg-yellow-100';
      case 'ROGUE': return 'text-red-600 bg-red-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const getAccuracyColor = (accuracy: number) => {
    if (accuracy >= 0.9) return 'text-green-600';
    if (accuracy >= 0.7) return 'text-yellow-600';
    return 'text-red-600';
  };

  return (
    <div className="overflow-x-auto">
      <table className="min-w-full bg-white dark:bg-zinc-900 rounded-lg shadow">
        <thead className="bg-gray-50 dark:bg-zinc-800">
          <tr>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Агент
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Роль
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Статус
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Точность
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Угрозы
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Последняя активность
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Аномалии
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-200 dark:divide-zinc-700">
          {agents.map((agent) => (
            <tr
              key={agent.id}
              onClick={() => onSelect(agent.id)}
              className="hover:bg-gray-50 dark:hover:bg-zinc-800 cursor-pointer transition-colors"
            >
              <td className="px-6 py-4 whitespace-nowrap">
                <div className="flex items-center">
                  <div className="flex-shrink-0 h-10 w-10">
                    <div className="h-10 w-10 rounded-full bg-gradient-to-r from-blue-500 to-purple-600 flex items-center justify-center">
                      <span className="text-white font-semibold text-sm">
                        {agent.name.split(' ').map(n => n[0]).join('').toUpperCase()}
                      </span>
                    </div>
                  </div>
                  <div className="ml-4">
                    <div className="text-sm font-medium text-gray-900 dark:text-white">
                      {agent.name}
                    </div>
                    <div className="text-sm text-gray-500 dark:text-gray-400">
                      ID: {agent.id}
                    </div>
                  </div>
                </div>
              </td>
              <td className="px-6 py-4 whitespace-nowrap">
                <div className="text-sm text-gray-900 dark:text-white">{agent.role}</div>
                {agent.location && (
                  <div className="text-sm text-gray-500 dark:text-gray-400">{agent.location}</div>
                )}
              </td>
              <td className="px-6 py-4 whitespace-nowrap">
                <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getStatusColor(agent.status)}`}>
                  {agent.status}
                </span>
              </td>
              <td className="px-6 py-4 whitespace-nowrap">
                <div className={`text-sm font-medium ${getAccuracyColor(agent.accuracy)}`}>
                  {(agent.accuracy * 100).toFixed(1)}%
                </div>
              </td>
              <td className="px-6 py-4 whitespace-nowrap">
                <div className="text-sm text-gray-900 dark:text-white">
                  {agent.threatsDetected}
                </div>
              </td>
              <td className="px-6 py-4 whitespace-nowrap">
                <div className="text-sm text-gray-500 dark:text-gray-400">
                  {new Date(agent.lastSeen).toLocaleString('ru-RU')}
                </div>
              </td>
              <td className="px-6 py-4 whitespace-nowrap">
                {agent.anomalyScore !== undefined && (
                  <div className="flex items-center">
                    <div className="w-16 bg-gray-200 dark:bg-zinc-700 rounded-full h-2">
                      <div 
                        className={`h-2 rounded-full ${
                          agent.anomalyScore > 0.7 ? 'bg-red-500' : 
                          agent.anomalyScore > 0.4 ? 'bg-yellow-500' : 'bg-green-500'
                        }`}
                        style={{ width: `${agent.anomalyScore * 100}%` }}
                      />
                    </div>
                    <span className="ml-2 text-xs text-gray-500 dark:text-gray-400">
                      {(agent.anomalyScore * 100).toFixed(0)}%
                    </span>
                  </div>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {agents.length === 0 && (
        <div className="text-center py-12">
          <div className="text-gray-500 dark:text-gray-400">
            Нет агентов, соответствующих критериям фильтра
          </div>
        </div>
      )}
    </div>
  );
};