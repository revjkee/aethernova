import { Card } from '../components/ui';

export const DataQualityPage = () => {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Data Quality</h1>
        <p className="mt-1 text-gray-600">
          Monitor and improve your data quality metrics
        </p>
      </div>

      <Card>
        <div className="text-center py-12">
          <div className="text-6xl mb-4">📊</div>
          <h3 className="text-lg font-medium text-gray-900 mb-2">Data Quality Dashboard</h3>
          <p className="text-gray-600">
            Comprehensive data quality monitoring and reporting tools coming soon.
          </p>
        </div>
      </Card>
    </div>
  );
};