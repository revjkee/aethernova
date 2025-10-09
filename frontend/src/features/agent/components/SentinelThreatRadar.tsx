// Sentinel Threat Radar Component

import React from 'react';

interface ThreatStats {
  active: number;
  inactive: number;
  quarantined: number;
  rogue: number;
}

interface SentinelThreatRadarProps {
  stats: ThreatStats;
}

export const SentinelThreatRadar: React.FC<SentinelThreatRadarProps> = ({ stats }) => {
  const total = stats.active + stats.inactive + stats.quarantined + stats.rogue;
  
  const getPercentage = (value: number) => {
    return total > 0 ? (value / total) * 100 : 0;
  };

  const threatLevel = () => {
    const roguePercentage = getPercentage(stats.rogue);
    const quarantinedPercentage = getPercentage(stats.quarantined);
    
    if (roguePercentage > 10) return { level: 'КРИТИЧЕСКИЙ', color: 'text-red-600', bgColor: 'bg-red-100' };
    if (quarantinedPercentage > 20) return { level: 'ВЫСОКИЙ', color: 'text-orange-600', bgColor: 'bg-orange-100' };
    if (quarantinedPercentage > 5) return { level: 'СРЕДНИЙ', color: 'text-yellow-600', bgColor: 'bg-yellow-100' };
    return { level: 'НИЗКИЙ', color: 'text-green-600', bgColor: 'bg-green-100' };
  };

  const currentThreatLevel = threatLevel();

  return (
    <div className="space-y-4">
      {/* Threat Level Indicator */}
      <div className="text-center">
        <div className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ${currentThreatLevel.color} ${currentThreatLevel.bgColor}`}>
          <div className={`w-2 h-2 rounded-full mr-2 ${currentThreatLevel.color.replace('text-', 'bg-')}`} />
          Уровень угрозы: {currentThreatLevel.level}
        </div>
      </div>

      {/* Radar Chart (Simplified Circular Progress) */}
      <div className="relative w-32 h-32 mx-auto">
        <svg className="w-32 h-32 transform -rotate-90" viewBox="0 0 128 128">
          {/* Background circles */}
          <circle
            cx="64"
            cy="64"
            r="56"
            stroke="currentColor"
            strokeWidth="2"
            fill="none"
            className="text-gray-200 dark:text-gray-700"
          />
          <circle
            cx="64"
            cy="64"
            r="40"
            stroke="currentColor"
            strokeWidth="1"
            fill="none"
            className="text-gray-200 dark:text-gray-700"
          />
          <circle
            cx="64"
            cy="64"
            r="24"
            stroke="currentColor"
            strokeWidth="1"
            fill="none"
            className="text-gray-200 dark:text-gray-700"
          />
          
          {/* Active agents arc */}
          <circle
            cx="64"
            cy="64"
            r="56"
            stroke="currentColor"
            strokeWidth="4"
            fill="none"
            strokeDasharray={`${getPercentage(stats.active) * 3.5} 350`}
            className="text-green-500"
          />
          
          {/* Quarantined agents arc */}
          <circle
            cx="64"
            cy="64"
            r="40"
            stroke="currentColor"
            strokeWidth="4"
            fill="none"
            strokeDasharray={`${getPercentage(stats.quarantined) * 2.5} 250`}
            className="text-yellow-500"
          />
          
          {/* Rogue agents arc */}
          <circle
            cx="64"
            cy="64"
            r="24"
            stroke="currentColor"
            strokeWidth="4"
            fill="none"
            strokeDasharray={`${getPercentage(stats.rogue) * 1.5} 150`}
            className="text-red-500"
          />
        </svg>
        
        {/* Center content */}
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="text-center">
            <div className="text-2xl font-bold text-gray-900 dark:text-white">{total}</div>
            <div className="text-xs text-gray-500 dark:text-gray-400">агентов</div>
          </div>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-2 gap-2 text-sm">
        <div className="flex items-center space-x-2">
          <div className="w-3 h-3 bg-green-500 rounded-full" />
          <span className="text-gray-700 dark:text-gray-300">Активные: {stats.active}</span>
        </div>
        <div className="flex items-center space-x-2">
          <div className="w-3 h-3 bg-gray-400 rounded-full" />
          <span className="text-gray-700 dark:text-gray-300">Неактивные: {stats.inactive}</span>
        </div>
        <div className="flex items-center space-x-2">
          <div className="w-3 h-3 bg-yellow-500 rounded-full" />
          <span className="text-gray-700 dark:text-gray-300">Карантин: {stats.quarantined}</span>
        </div>
        <div className="flex items-center space-x-2">
          <div className="w-3 h-3 bg-red-500 rounded-full" />
          <span className="text-gray-700 dark:text-gray-300">Изгои: {stats.rogue}</span>
        </div>
      </div>

      {/* Metrics */}
      <div className="border-t dark:border-gray-600 pt-3 space-y-2">
        <div className="flex justify-between text-sm">
          <span className="text-gray-600 dark:text-gray-400">Эффективность:</span>
          <span className="font-medium text-gray-900 dark:text-white">
            {total > 0 ? Math.round((stats.active / total) * 100) : 0}%
          </span>
        </div>
        <div className="flex justify-between text-sm">
          <span className="text-gray-600 dark:text-gray-400">Риск компрометации:</span>
          <span className={`font-medium ${currentThreatLevel.color}`}>
            {Math.round(getPercentage(stats.rogue + stats.quarantined))}%
          </span>
        </div>
      </div>
    </div>
  );
};