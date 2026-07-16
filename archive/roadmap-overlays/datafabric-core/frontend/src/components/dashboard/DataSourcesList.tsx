import React from 'react';
import { Card, StatusBadge } from '../ui';
import { DataSource } from '../../types';
import { formatDistanceToNow } from 'date-fns';

interface DataSourcesListProps {
  dataSources: DataSource[];
  loading?: boolean;
}

export const DataSourcesList: React.FC<DataSourcesListProps> = ({
  dataSources,
  loading = false
}) => {
  if (loading) {
    return (
      <Card title="Data Sources" className="space-y-4">
        {[...Array(3)].map((_, i) => (
          <div key={i} className="animate-pulse">
            <div className="flex items-center justify-between p-4 border rounded-lg">
              <div className="space-y-2">
                <div className="h-4 bg-gray-200 rounded w-32"></div>
                <div className="h-3 bg-gray-200 rounded w-24"></div>
              </div>
              <div className="h-6 bg-gray-200 rounded-full w-16"></div>
            </div>
          </div>
        ))}
      </Card>
    );
  }

  return (
    <Card title="Data Sources" subtitle={`${dataSources.length} configured`}>
      <div className="space-y-3">
        {dataSources.map((source) => (
          <div
            key={source.id}
            className="flex items-center justify-between p-4 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors"
          >
            <div className="flex-1 min-w-0">
              <div className="flex items-center space-x-3">
                <div className="flex-shrink-0">
                  <div className="w-8 h-8 bg-blue-100 rounded-lg flex items-center justify-center">
                    {getSourceIcon(source.type)}
                  </div>
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-gray-900 truncate">
                    {source.name}
                  </p>
                  <div className="flex items-center space-x-2 text-xs text-gray-500">
                    <span className="capitalize">{source.type}</span>
                    <span>•</span>
                    <span>{source.recordCount.toLocaleString()} records</span>
                    <span>•</span>
                    <span>Last sync: {formatDistanceToNow(source.lastSync, { addSuffix: true })}</span>
                  </div>
                </div>
              </div>
            </div>
            <div className="flex-shrink-0">
              <StatusBadge status={source.status} />
            </div>
          </div>
        ))}
      </div>
    </Card>
  );
};

const getSourceIcon = (type: DataSource['type']) => {
  const iconMap = {
    database: '🗄️',
    api: '🔌',
    file: '📄',
    stream: '🌊',
    cloud: '☁️'
  };
  return iconMap[type] || '📊';
};