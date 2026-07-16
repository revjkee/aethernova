import React, { useEffect } from 'react';
import { Activity, AlertTriangle, CheckCircle, Clock, Wifi, WifiOff } from 'lucide-react';
import { useRealTimeObservability } from '../hooks/useRealTimeMetrics';
import { useNotifications } from '../components/NotificationSystem';
import { useTranslation } from 'react-i18next';

const Dashboard: React.FC = () => {
  const { t } = useTranslation();
  const { metrics, alerts, connected } = useRealTimeObservability();
  const { notifySuccess, notifyWarning, notifyError } = useNotifications();



  // Handle new alerts
  useEffect(() => {
    if (alerts.length > 0) {
      const latestAlert = alerts[0];
      if (!latestAlert.resolved) {
        switch (latestAlert.level) {
          case 'error':
          case 'critical':
            notifyError(latestAlert.message, latestAlert.source);
            break;
          case 'warning':
            notifyWarning(latestAlert.message, latestAlert.source);
            break;
          default:
            notifySuccess(latestAlert.message, latestAlert.source);
        }
      }
    }
  }, [alerts, notifyError, notifyWarning, notifySuccess]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div className="flex items-center space-x-4">
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            {t('dashboard.title')}
          </h1>
          <div className="flex items-center space-x-2">
            {connected ? (
              <Wifi className="h-5 w-5 text-green-500" />
            ) : (
              <WifiOff className="h-5 w-5 text-red-500" />
            )}
            <span className={`text-sm font-medium ${connected ? 'text-green-600' : 'text-red-600'}`}>
              {connected ? t('dashboard.live') : t('dashboard.disconnected')}
            </span>
          </div>
        </div>
        <div className="text-sm text-gray-500 dark:text-gray-400">
          Last updated: {new Date(metrics.lastUpdate).toLocaleTimeString()}
        </div>
      </div>

      {/* Quick Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="metric-card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">
                {t('dashboard.systemHealth')}
              </p>
              <p className="text-2xl font-semibold text-green-600">98.5{t('dashboard.percent')}</p>
            </div>
            <CheckCircle className="h-8 w-8 text-green-500" />
          </div>
        </div>

        <div className="metric-card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">
                {t('dashboard.activeAlerts')}
              </p>
              <p className="text-2xl font-semibold text-yellow-600">3</p>
            </div>
            <AlertTriangle className="h-8 w-8 text-yellow-500" />
          </div>
        </div>

        <div className="metric-card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">
                {t('dashboard.responseTime')}
              </p>
              <p className="text-2xl font-semibold text-blue-600">{metrics.responseTime}{t('dashboard.ms')}</p>
            </div>
            <Clock className="h-8 w-8 text-blue-500" />
          </div>
        </div>

        <div className="metric-card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">
                {t('dashboard.uptime')}
              </p>
              <p className="text-2xl font-semibold text-purple-600">99.9{t('dashboard.percent')}</p>
            </div>
            <Activity className="h-8 w-8 text-purple-500" />
          </div>
        </div>
      </div>

      {/* Grafana Dashboards */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <div className="card">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            TeslaAI Core Metrics
          </h3>
          <div className="h-96 bg-gray-100 dark:bg-gray-700 rounded-lg flex items-center justify-center">
            <iframe
              src="/api/grafana/d-solo/teslaai-core/teslaai-core-dashboard?orgId=1&theme=light&panelId=1"
              width="100%"
              height="100%"
              frameBorder="0"
              className="rounded-lg"
              title="Grafana Panel"
            />
          </div>
        </div>

        <div className="card">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            System Overview
          </h3>
          <div className="h-96 bg-gray-100 dark:bg-gray-700 rounded-lg flex items-center justify-center">
            <iframe
              src="/api/grafana/d-solo/teslaai-core/teslaai-dashboard-v2?orgId=1&theme=light&panelId=1"
              width="100%"
              height="100%"
              frameBorder="0"
              className="rounded-lg"
              title="Grafana Panel"
            />
          </div>
        </div>
      </div>

      {/* Recent Activity */}
      <div className="card">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          Recent Activity
        </h3>
        <div className="space-y-3">
          {[
            { time: '10:30 AM', event: 'System health check completed', status: 'success' },
            { time: '10:25 AM', event: 'High memory usage detected on node-3', status: 'warning' },
            { time: '10:20 AM', event: 'Agent restart completed successfully', status: 'success' },
            { time: '10:15 AM', event: 'New alert rule activated', status: 'info' },
          ].map((activity, index) => (
            <div key={index} className="flex items-center space-x-3 p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
              <div className={`w-2 h-2 rounded-full ${
                activity.status === 'success' ? 'bg-green-400' :
                activity.status === 'warning' ? 'bg-yellow-400' :
                'bg-blue-400'
              }`}></div>
              <div className="flex-1">
                <p className="text-sm text-gray-900 dark:text-white">{activity.event}</p>
                <p className="text-xs text-gray-500 dark:text-gray-400">{activity.time}</p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default Dashboard;