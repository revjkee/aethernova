import { Card } from '../components/ui';

export const MonitoringPage = () => {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">System Monitoring</h1>
        <p className="mt-1 text-gray-600">
          Real-time system health and performance monitoring
        </p>
      </div>

      <Card>
        <div className="text-center py-12">
          <div className="text-6xl mb-4">👁️</div>
          <h3 className="text-lg font-medium text-gray-900 mb-2">Monitoring Dashboard</h3>
          <p className="text-gray-600">
            Comprehensive system monitoring and alerting coming soon.
          </p>
        </div>
      </Card>
    </div>
  );
};