// Sentinel Agent Modal Component

import React from 'react';

interface SentinelAgentModalProps {
  agentId: string;
}

export const SentinelAgentModal: React.FC<SentinelAgentModalProps> = ({ agentId }) => {
  // Mock agent data based on ID
  const agentData = {
    id: agentId,
    name: `Agent ${agentId.split('-')[1]?.toUpperCase() || 'Unknown'}`,
    role: 'Security Monitor',
    status: 'ACTIVE' as const,
    version: '2.1.3',
    uptime: '15d 7h 23m',
    location: 'DMZ-1',
    lastSeen: new Date().toISOString(),
    metrics: {
      threatsDetected: 42,
      falsePositives: 3,
      accuracy: 0.92,
      responseTime: '1.2ms',
      memoryUsage: '256MB',
      cpuUsage: '12%'
    },
    capabilities: [
      'Network Traffic Analysis',
      'Behavioral Detection',
      'Anomaly Recognition',
      'Real-time Monitoring',
      'Threat Classification'
    ],
    recentActivities: [
      {
        id: '1',
        timestamp: new Date(Date.now() - 300000).toISOString(),
        action: 'Blocked suspicious IP',
        details: '192.168.1.45 attempting unauthorized access'
      },
      {
        id: '2',
        timestamp: new Date(Date.now() - 600000).toISOString(),
        action: 'Updated threat signatures',
        details: 'Downloaded 1,247 new threat patterns'
      },
      {
        id: '3',
        timestamp: new Date(Date.now() - 900000).toISOString(),
        action: 'System scan completed',
        details: 'Scanned 15,234 files, no threats found'
      }
    ]
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'ACTIVE': return 'text-green-600 bg-green-100';
      case 'INACTIVE': return 'text-gray-600 bg-gray-100';
      case 'QUARANTINED': return 'text-yellow-600 bg-yellow-100';
      case 'ROGUE': return 'text-red-600 bg-red-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  return (
    <div className="bg-white dark:bg-zinc-900 rounded-lg max-w-4xl w-full max-h-[90vh] overflow-y-auto">
      {/* Header */}
      <div className="px-6 py-4 border-b border-gray-200 dark:border-zinc-700">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-2xl font-bold text-gray-900 dark:text-white">
              {agentData.name}
            </h2>
            <p className="text-gray-600 dark:text-gray-400">{agentData.role}</p>
          </div>
          <span className={`px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(agentData.status)}`}>
            {agentData.status}
          </span>
        </div>
      </div>

      <div className="p-6 space-y-6">
        {/* Basic Info */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="space-y-4">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              Основная информация
            </h3>
            <div className="space-y-2">
              <div className="flex justify-between">
                <span className="text-gray-600 dark:text-gray-400">ID агента:</span>
                <span className="text-gray-900 dark:text-white font-mono">{agentData.id}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-600 dark:text-gray-400">Версия:</span>
                <span className="text-gray-900 dark:text-white">{agentData.version}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-600 dark:text-gray-400">Время работы:</span>
                <span className="text-gray-900 dark:text-white">{agentData.uptime}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-600 dark:text-gray-400">Местоположение:</span>
                <span className="text-gray-900 dark:text-white">{agentData.location}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-600 dark:text-gray-400">Последняя активность:</span>
                <span className="text-gray-900 dark:text-white">
                  {new Date(agentData.lastSeen).toLocaleString('ru-RU')}
                </span>
              </div>
            </div>
          </div>

          {/* Performance Metrics */}
          <div className="space-y-4">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              Метрики производительности
            </h3>
            <div className="space-y-3">
              <div>
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600 dark:text-gray-400">Точность детекции</span>
                  <span className="text-gray-900 dark:text-white">{(agentData.metrics.accuracy * 100).toFixed(1)}%</span>
                </div>
                <div className="w-full bg-gray-200 dark:bg-zinc-700 rounded-full h-2 mt-1">
                  <div 
                    className="bg-green-500 h-2 rounded-full" 
                    style={{ width: `${agentData.metrics.accuracy * 100}%` }}
                  />
                </div>
              </div>
              
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div className="flex justify-between">
                  <span className="text-gray-600 dark:text-gray-400">Угрозы:</span>
                  <span className="text-gray-900 dark:text-white">{agentData.metrics.threatsDetected}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600 dark:text-gray-400">Ложные:</span>
                  <span className="text-gray-900 dark:text-white">{agentData.metrics.falsePositives}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600 dark:text-gray-400">Время ответа:</span>
                  <span className="text-gray-900 dark:text-white">{agentData.metrics.responseTime}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600 dark:text-gray-400">CPU:</span>
                  <span className="text-gray-900 dark:text-white">{agentData.metrics.cpuUsage}</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Capabilities */}
        <div className="space-y-4">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
            Возможности агента
          </h3>
          <div className="flex flex-wrap gap-2">
            {agentData.capabilities.map((capability, index) => (
              <span 
                key={index}
                className="px-3 py-1 bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-200 text-sm rounded-full"
              >
                {capability}
              </span>
            ))}
          </div>
        </div>

        {/* Recent Activities */}
        <div className="space-y-4">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
            Недавняя активность
          </h3>
          <div className="space-y-3">
            {agentData.recentActivities.map((activity) => (
              <div 
                key={activity.id}
                className="p-3 border border-gray-200 dark:border-zinc-700 rounded-lg"
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="font-medium text-gray-900 dark:text-white">
                    {activity.action}
                  </span>
                  <span className="text-sm text-gray-500 dark:text-gray-400">
                    {new Date(activity.timestamp).toLocaleTimeString('ru-RU')}
                  </span>
                </div>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  {activity.details}
                </p>
              </div>
            ))}
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex space-x-3 pt-4 border-t border-gray-200 dark:border-zinc-700">
          <button className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors">
            Обновить конфигурацию
          </button>
          <button className="px-4 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700 transition-colors">
            Перезапустить агента
          </button>
          <button className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors">
            Поместить в карантин
          </button>
        </div>
      </div>
    </div>
  );
};