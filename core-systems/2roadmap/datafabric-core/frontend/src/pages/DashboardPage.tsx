import { useTranslation } from 'react-i18next';
import { DashboardMetricsGrid } from '../components/dashboard/DashboardMetrics';
import { DataSourcesList } from '../components/dashboard/DataSourcesList';
import { PipelinesOverview } from '../components/dashboard/PipelinesOverview';
import { useDashboardMetrics, useDataSources, useDataPipelines } from '../hooks/useApi';

export const DashboardPage = () => {
  const { t } = useTranslation();
  const { data: metrics, loading: metricsLoading } = useDashboardMetrics();
  const { data: dataSources, loading: sourcesLoading } = useDataSources();
  const { data: pipelines, loading: pipelinesLoading } = useDataPipelines();

  return (
    <div className="space-y-8">
      {/* Hero Section */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <div className="max-w-3xl">
          <h1 className="text-2xl font-bold text-gray-900">{t('dashboard.title')}</h1>
          <p className="mt-2 text-gray-600">
            {t('dashboard.subtitle')}
          </p>
        </div>
      </div>

      {/* Metrics Grid */}
      <DashboardMetricsGrid metrics={metrics} loading={metricsLoading} />

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <div className="space-y-8">
          <DataSourcesList dataSources={dataSources} loading={sourcesLoading} />
        </div>
        
        <div className="space-y-8">
          <PipelinesOverview pipelines={pipelines} loading={pipelinesLoading} />
        </div>
      </div>
    </div>
  );
};