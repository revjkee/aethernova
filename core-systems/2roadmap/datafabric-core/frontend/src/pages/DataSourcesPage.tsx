import { useTranslation } from 'react-i18next';
import { Card, Button, StatusBadge } from '../components/ui';
import { useDataSources } from '../hooks/useApi';
import { formatDistanceToNow } from 'date-fns';

export const DataSourcesPage = () => {
  const { t } = useTranslation();
  const { data: dataSources, loading } = useDataSources();

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">{t('dataSources.title')}</h1>
          <p className="mt-1 text-gray-600">
            {t('dataSources.subtitle')}
          </p>
        </div>
        <Button>{t('dataSources.addNew')}</Button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <Card className="text-center">
          <div className="text-2xl font-bold text-blue-600">{dataSources.length}</div>
          <div className="text-sm text-gray-600">Total Sources</div>
        </Card>
        <Card className="text-center">
          <div className="text-2xl font-bold text-green-600">
            {dataSources.filter(s => s.status === 'connected').length}
          </div>
          <div className="text-sm text-gray-600">Connected</div>
        </Card>
        <Card className="text-center">
          <div className="text-2xl font-bold text-yellow-600">
            {dataSources.filter(s => s.status === 'syncing').length}
          </div>
          <div className="text-sm text-gray-600">Syncing</div>
        </Card>
        <Card className="text-center">
          <div className="text-2xl font-bold text-red-600">
            {dataSources.filter(s => s.status === 'error').length}
          </div>
          <div className="text-sm text-gray-600">Error</div>
        </Card>
      </div>

      {/* Data Sources List */}
      <Card title="All Data Sources">
        {loading ? (
          <div className="space-y-4">
            {[...Array(5)].map((_, i) => (
              <div key={i} className="animate-pulse p-4 border rounded-lg">
                <div className="flex justify-between items-start">
                  <div className="space-y-2">
                    <div className="h-4 bg-gray-200 rounded w-48"></div>
                    <div className="h-3 bg-gray-200 rounded w-32"></div>
                  </div>
                  <div className="h-6 bg-gray-200 rounded-full w-20"></div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Data Source
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Type
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Records
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Last Sync
                  </th>
                  <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {dataSources.map((source) => (
                  <tr key={source.id} className="hover:bg-gray-50">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        <div className="flex-shrink-0 h-8 w-8">
                          <div className="h-8 w-8 bg-blue-100 rounded-lg flex items-center justify-center text-sm">
                            {getSourceIcon(source.type)}
                          </div>
                        </div>
                        <div className="ml-4">
                          <div className="text-sm font-medium text-gray-900">
                            {source.name}
                          </div>
                          <div className="text-sm text-gray-500">
                            v{source.schemaVersion}
                          </div>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      <span className="capitalize">{source.type}</span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <StatusBadge status={source.status} />
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      {source.recordCount.toLocaleString()}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {formatDistanceToNow(source.lastSync, { addSuffix: true })}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                      <div className="flex justify-end space-x-2">
                        <Button size="sm" variant="ghost">Edit</Button>
                        <Button size="sm" variant="ghost">Test</Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
};

const getSourceIcon = (type: string) => {
  const iconMap: Record<string, string> = {
    database: '🗄️',
    api: '🔌',
    file: '📄',
    stream: '🌊',
    cloud: '☁️'
  };
  return iconMap[type] || '📊';
};