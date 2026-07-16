import React from 'react';
import { Card, StatusBadge, Badge } from '../ui';
import { DataPipeline } from '../../types';
import { formatDistanceToNow } from 'date-fns';

interface PipelinesOverviewProps {
  pipelines: DataPipeline[];
  loading?: boolean;
}

export const PipelinesOverview: React.FC<PipelinesOverviewProps> = ({
  pipelines,
  loading = false
}) => {
  if (loading) {
    return (
      <Card title="Data Pipelines" className="space-y-4">
        {[...Array(2)].map((_, i) => (
          <div key={i} className="animate-pulse">
            <div className="p-4 border rounded-lg space-y-3">
              <div className="flex justify-between items-start">
                <div className="space-y-2">
                  <div className="h-4 bg-gray-200 rounded w-40"></div>
                  <div className="h-3 bg-gray-200 rounded w-56"></div>
                </div>
                <div className="h-6 bg-gray-200 rounded-full w-16"></div>
              </div>
              <div className="h-2 bg-gray-200 rounded-full w-full"></div>
            </div>
          </div>
        ))}
      </Card>
    );
  }

  return (
    <Card title="Data Pipelines" subtitle={`${pipelines.length} configured`}>
      <div className="space-y-4">
        {pipelines.map((pipeline) => (
          <div
            key={pipeline.id}
            className="p-4 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors"
          >
            <div className="flex justify-between items-start mb-3">
              <div className="flex-1 min-w-0">
                <h4 className="text-sm font-medium text-gray-900 truncate">
                  {pipeline.name}
                </h4>
                <p className="text-xs text-gray-500 mt-1 line-clamp-2">
                  {pipeline.description}
                </p>
              </div>
              <div className="flex-shrink-0 ml-4">
                <StatusBadge status={pipeline.status} />
              </div>
            </div>

            {/* Progress Bar */}
            {pipeline.status === 'running' && (
              <div className="mb-3">
                <div className="flex justify-between text-xs text-gray-600 mb-1">
                  <span>Progress</span>
                  <span>{pipeline.progress}%</span>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-2">
                  <div
                    className="bg-blue-600 h-2 rounded-full transition-all duration-300"
                    style={{ width: `${pipeline.progress}%` }}
                  />
                </div>
              </div>
            )}

            {/* Metrics */}
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
              <div>
                <span className="text-gray-500">Records Processed</span>
                <p className="font-medium text-gray-900">
                  {pipeline.metrics.recordsProcessed.toLocaleString()}
                </p>
              </div>
              <div>
                <span className="text-gray-500">Success Rate</span>
                <p className="font-medium text-gray-900">
                  {pipeline.metrics.successRate}%
                </p>
              </div>
              <div>
                <span className="text-gray-500">Avg Time</span>
                <p className="font-medium text-gray-900">
                  {pipeline.metrics.avgProcessingTime}s
                </p>
              </div>
              <div>
                <span className="text-gray-500">Last Run</span>
                <p className="font-medium text-gray-900">
                  {formatDistanceToNow(pipeline.lastRun, { addSuffix: true })}
                </p>
              </div>
            </div>

            {/* Schedule and Transformations */}
            <div className="mt-3 pt-3 border-t border-gray-100">
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant="info" size="sm">
                  {getScheduleLabel(pipeline.config.schedule)}
                </Badge>
                <Badge variant="default" size="sm">
                  {pipeline.config.transformations.length} transformations
                </Badge>
                {pipeline.metrics.errorCount > 0 && (
                  <Badge variant="warning" size="sm">
                    {pipeline.metrics.errorCount} errors
                  </Badge>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>
    </Card>
  );
};

const getScheduleLabel = (schedule: string): string => {
  if (schedule === 'continuous') return 'Real-time';
  if (schedule.includes('*/2')) return 'Every 2 hours';
  if (schedule.includes('*/1')) return 'Hourly';
  if (schedule.includes('0 0')) return 'Daily';
  return 'Custom schedule';
};