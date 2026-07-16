import { useTranslation } from 'react-i18next';
import { Card, Button, StatusBadge, Badge } from '../components/ui';
import { useDataPipelines } from '../hooks/useApi';
import { formatDistanceToNow } from 'date-fns';

export const PipelinesPage = () => {
  const { t } = useTranslation();
  const { data: pipelines, loading } = useDataPipelines();

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">{t('pipelines.title')}</h1>
          <p className="mt-1 text-gray-600">
            {t('pipelines.subtitle')}
          </p>
        </div>
        <Button>{t('pipelines.addNew')}</Button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <Card className="text-center">
          <div className="text-2xl font-bold text-blue-600">{pipelines.length}</div>
          <div className="text-sm text-gray-600">Total Pipelines</div>
        </Card>
        <Card className="text-center">
          <div className="text-2xl font-bold text-green-600">
            {pipelines.filter(p => p.status === 'running').length}
          </div>
          <div className="text-sm text-gray-600">Running</div>
        </Card>
        <Card className="text-center">
          <div className="text-2xl font-bold text-yellow-600">
            {pipelines.filter(p => p.status === 'paused').length}
          </div>
          <div className="text-sm text-gray-600">Paused</div>
        </Card>
        <Card className="text-center">
          <div className="text-2xl font-bold text-red-600">
            {pipelines.filter(p => p.status === 'error').length}
          </div>
          <div className="text-sm text-gray-600">Error</div>
        </Card>
      </div>

      {/* Pipelines List */}
      <div className="space-y-4">
        {loading ? (
          [...Array(3)].map((_, i) => (
            <Card key={i} className="animate-pulse">
              <div className="p-6 space-y-4">
                <div className="flex justify-between">
                  <div className="space-y-2">
                    <div className="h-4 bg-gray-200 rounded w-48"></div>
                    <div className="h-3 bg-gray-200 rounded w-64"></div>
                  </div>
                  <div className="h-6 bg-gray-200 rounded-full w-20"></div>
                </div>
                <div className="h-2 bg-gray-200 rounded-full w-full"></div>
              </div>
            </Card>
          ))
        ) : (
          pipelines.map((pipeline) => (
            <Card key={pipeline.id}>
              <div className="p-6">
                <div className="flex justify-between items-start mb-4">
                  <div className="flex-1">
                    <h3 className="text-lg font-medium text-gray-900">{pipeline.name}</h3>
                    <p className="text-sm text-gray-600 mt-1">{pipeline.description}</p>
                  </div>
                  <div className="flex items-center space-x-3">
                    <StatusBadge status={pipeline.status} />
                    <div className="flex space-x-2">
                      <Button size="sm" variant="ghost">Edit</Button>
                      <Button size="sm" variant="ghost">Logs</Button>
                    </div>
                  </div>
                </div>

                {/* Progress Bar */}
                {pipeline.status === 'running' && (
                  <div className="mb-4">
                    <div className="flex justify-between text-sm text-gray-600 mb-2">
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

                {/* Metrics Grid */}
                <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-4">
                  <div className="bg-gray-50 p-3 rounded-lg">
                    <div className="text-xs text-gray-500">Records Processed</div>
                    <div className="text-lg font-semibold text-gray-900">
                      {pipeline.metrics.recordsProcessed.toLocaleString()}
                    </div>
                  </div>
                  <div className="bg-gray-50 p-3 rounded-lg">
                    <div className="text-xs text-gray-500">Success Rate</div>
                    <div className="text-lg font-semibold text-gray-900">
                      {pipeline.metrics.successRate}%
                    </div>
                  </div>
                  <div className="bg-gray-50 p-3 rounded-lg">
                    <div className="text-xs text-gray-500">Avg Processing Time</div>
                    <div className="text-lg font-semibold text-gray-900">
                      {pipeline.metrics.avgProcessingTime}s
                    </div>
                  </div>
                  <div className="bg-gray-50 p-3 rounded-lg">
                    <div className="text-xs text-gray-500">Error Count</div>
                    <div className="text-lg font-semibold text-red-600">
                      {pipeline.metrics.errorCount}
                    </div>
                  </div>
                </div>

                {/* Schedule and Transformations */}
                <div className="flex flex-wrap items-center justify-between pt-4 border-t border-gray-200">
                  <div className="flex flex-wrap gap-2 mb-2 lg:mb-0">
                    <Badge variant="info" size="sm">
                      {getScheduleLabel(pipeline.config.schedule)}
                    </Badge>
                    <Badge variant="default" size="sm">
                      {pipeline.config.transformations.length} transformations
                    </Badge>
                    <Badge variant="default" size="sm">
                      {pipeline.config.validators.length} validators
                    </Badge>
                  </div>
                  <div className="text-sm text-gray-500">
                    Last run: {formatDistanceToNow(pipeline.lastRun, { addSuffix: true })}
                    {pipeline.nextRun && (
                      <span className="ml-2">
                        • Next: {formatDistanceToNow(pipeline.nextRun, { addSuffix: true })}
                      </span>
                    )}
                  </div>
                </div>
              </div>
            </Card>
          ))
        )}
      </div>
    </div>
  );
};

const getScheduleLabel = (schedule: string): string => {
  if (schedule === 'continuous') return 'Real-time';
  if (schedule.includes('*/2')) return 'Every 2 hours';
  if (schedule.includes('*/1')) return 'Hourly';
  if (schedule.includes('0 0')) return 'Daily';
  return 'Custom schedule';
};