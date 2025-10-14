import React from 'react';
import { Card } from '../ui';
import { DashboardMetrics } from '../../types';

interface MetricCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  trend?: 'up' | 'down' | 'stable';
  color?: 'blue' | 'green' | 'yellow' | 'red' | 'purple' | 'gray';
  loading?: boolean;
}

const MetricCard: React.FC<MetricCardProps> = ({
  title,
  value,
  subtitle,
  trend,
  color = 'blue',
  loading = false
}) => {
  const colorClasses = {
    blue: 'text-blue-600',
    green: 'text-green-600',
    yellow: 'text-yellow-600',
    red: 'text-red-600',
    purple: 'text-purple-600',
    gray: 'text-gray-600'
  };

  const trendIcons = {
    up: '↗️',
    down: '↘️',
    stable: '→'
  };

  if (loading) {
    return (
      <Card className="animate-pulse">
        <div className="h-4 bg-gray-200 rounded w-3/4 mb-2"></div>
        <div className="h-8 bg-gray-200 rounded w-1/2 mb-2"></div>
        <div className="h-3 bg-gray-200 rounded w-2/3"></div>
      </Card>
    );
  }

  return (
    <Card>
      <div className="space-y-2">
        <h3 className="text-sm font-medium text-gray-500">{title}</h3>
        <div className="flex items-baseline space-x-2">
          <p className={`text-3xl font-bold ${colorClasses[color]}`}>
            {typeof value === 'number' && value % 1 !== 0 ? value.toFixed(1) : value}
          </p>
          {trend && (
            <span className="text-sm text-gray-500">
              {trendIcons[trend]}
            </span>
          )}
        </div>
        {subtitle && (
          <p className="text-sm text-gray-600">{subtitle}</p>
        )}
      </div>
    </Card>
  );
};

interface DashboardMetricsGridProps {
  metrics: DashboardMetrics | null;
  loading?: boolean;
}

export const DashboardMetricsGrid: React.FC<DashboardMetricsGridProps> = ({
  metrics,
  loading = false
}) => {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
      <MetricCard
        title="Active Data Sources"
        value={metrics?.activeDataSources ?? 0}
        subtitle={`${metrics?.totalDataSources ?? 0} total`}
        color="blue"
        trend="stable"
        loading={loading}
      />
      
      <MetricCard
        title="Running Pipelines"
        value={metrics?.runningPipelines ?? 0}
        subtitle={`${metrics?.totalPipelines ?? 0} total`}
        color="green"
        trend="up"
        loading={loading}
      />
      
      <MetricCard
        title="Data Quality"
        value={metrics ? `${metrics.avgDataQuality}%` : '0%'}
        subtitle="Average score"
        color="purple"
        trend="up"
        loading={loading}
      />
      
      <MetricCard
        title="Active Alerts"
        value={metrics?.totalAlerts ?? 0}
        subtitle={`${metrics?.unreadAlerts ?? 0} unread`}
        color={metrics && metrics.totalAlerts > 5 ? 'red' : 'yellow'}
        trend="down"
        loading={loading}
      />
    </div>
  );
};