import React, { useState, useEffect } from 'react';
import { Plus, Edit, Trash2, Bell, BellOff, Eye, EyeOff } from 'lucide-react';
import { useTranslation } from 'react-i18next';

export interface AlertRule {
  id: string;
  name: string;
  description: string;
  metric: string;
  condition: 'greater_than' | 'less_than' | 'equal_to' | 'not_equal_to';
  threshold: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  enabled: boolean;
  notifications: {
    email: boolean;
    webhook: boolean;
    push: boolean;
  };
  cooldown: number; // minutes
  created: string;
  lastTriggered?: string;
}

interface AlertManagementProps {
  className?: string;
}

const AlertManagement: React.FC<AlertManagementProps> = ({ className = '' }) => {
  const { t } = useTranslation();
  const [alerts, setAlerts] = useState<AlertRule[]>([]);
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  
  const editAlert = (alert: AlertRule) => {
    console.log('Edit alert:', alert);
    // TODO: Implement edit functionality
  };

  // Initialize with mock data
  useEffect(() => {
    const mockAlerts: AlertRule[] = [
      {
        id: 'alert_1',
        name: 'High CPU Usage',
        description: 'Alert when CPU usage exceeds 80%',
        metric: 'cpu_usage',
        condition: 'greater_than',
        threshold: 80,
        severity: 'high',
        enabled: true,
        notifications: { email: true, webhook: false, push: true },
        cooldown: 5,
        created: '2025-01-10T10:00:00Z',
        lastTriggered: '2025-01-13T14:30:00Z',
      },
      {
        id: 'alert_2',
        name: 'Low Memory Available',
        description: 'Alert when available memory is below 10%',
        metric: 'memory_available',
        condition: 'less_than',
        threshold: 10,
        severity: 'critical',
        enabled: true,
        notifications: { email: true, webhook: true, push: true },
        cooldown: 2,
        created: '2025-01-10T11:00:00Z',
      },
      {
        id: 'alert_3',
        name: 'Agent Offline',
        description: 'Alert when agents go offline',
        metric: 'active_agents',
        condition: 'less_than',
        threshold: 300,
        severity: 'medium',
        enabled: false,
        notifications: { email: true, webhook: false, push: false },
        cooldown: 10,
        created: '2025-01-10T12:00:00Z',
      },
    ];
    setAlerts(mockAlerts);
  }, []);

  const filteredAlerts = alerts.filter(alert =>
    alert.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    alert.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
    alert.metric.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const toggleAlertEnabled = (id: string) => {
    setAlerts(prev => prev.map(alert =>
      alert.id === id ? { ...alert, enabled: !alert.enabled } : alert
    ));
  };

  const deleteAlert = (id: string) => {
    if (window.confirm('Are you sure you want to delete this alert rule?')) {
      setAlerts(prev => prev.filter(alert => alert.id !== id));
    }
  };

  const getSeverityColor = (severity: AlertRule['severity']) => {
    switch (severity) {
      case 'low': return 'text-blue-600 bg-blue-100 dark:bg-blue-900 dark:text-blue-300';
      case 'medium': return 'text-yellow-600 bg-yellow-100 dark:bg-yellow-900 dark:text-yellow-300';
      case 'high': return 'text-orange-600 bg-orange-100 dark:bg-orange-900 dark:text-orange-300';
      case 'critical': return 'text-red-600 bg-red-100 dark:bg-red-900 dark:text-red-300';
    }
  };

  const getConditionText = (condition: AlertRule['condition']) => {
    switch (condition) {
      case 'greater_than': return '>';
      case 'less_than': return '<';
      case 'equal_to': return '=';
      case 'not_equal_to': return '≠';
    }
  };

  return (
    <div className={`space-y-6 ${className}`}>
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold text-gray-900 dark:text-white">
            {t('alerts.title')}
          </h2>
          <p className="text-gray-600 dark:text-gray-400 mt-1">
            Настройка и управление правилами системных оповещений
          </p>
        </div>
        <button
          onClick={() => setIsCreateModalOpen(true)}
          className="flex items-center space-x-2 px-4 py-2 bg-primary-600 hover:bg-primary-700 text-white font-medium rounded-lg transition-colors"
        >
          <Plus className="h-4 w-4" />
          <span>Create Alert</span>
        </button>
      </div>

      {/* Search Bar */}
      <div className="relative">
        <input
          type="text"
          placeholder="Search alert rules..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="w-full pl-4 pr-4 py-3 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400 focus:ring-2 focus:ring-primary-500 focus:border-transparent"
        />
      </div>

      {/* Alerts List */}
      <div className="grid gap-4">
        {filteredAlerts.map(alert => (
          <div
            key={alert.id}
            className="bg-white dark:bg-gray-800 rounded-lg shadow-md border border-gray-200 dark:border-gray-700 p-6"
          >
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <div className="flex items-center space-x-3 mb-2">
                  <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                    {alert.name}
                  </h3>
                  <span className={`px-2 py-1 text-xs font-medium rounded-full ${getSeverityColor(alert.severity)}`}>
                    {alert.severity.toUpperCase()}
                  </span>
                  {alert.enabled ? (
                    <span className="flex items-center text-green-600 dark:text-green-400 text-sm">
                      <Bell className="h-4 w-4 mr-1" />
                      Active
                    </span>
                  ) : (
                    <span className="flex items-center text-gray-500 dark:text-gray-400 text-sm">
                      <BellOff className="h-4 w-4 mr-1" />
                      Disabled
                    </span>
                  )}
                </div>
                
                <p className="text-gray-600 dark:text-gray-300 mb-3">
                  {alert.description}
                </p>

                <div className="flex items-center space-x-6 text-sm text-gray-500 dark:text-gray-400">
                  <span>
                    <strong>Condition:</strong> {alert.metric} {getConditionText(alert.condition)} {alert.threshold}
                  </span>
                  <span>
                    <strong>Cooldown:</strong> {alert.cooldown} min
                  </span>
                  {alert.lastTriggered && (
                    <span>
                      <strong>Last triggered:</strong> {new Date(alert.lastTriggered).toLocaleString()}
                    </span>
                  )}
                </div>

                <div className="flex items-center space-x-4 mt-3">
                  {alert.notifications.email && (
                    <span className="px-2 py-1 bg-blue-100 dark:bg-blue-900 text-blue-700 dark:text-blue-300 text-xs rounded">
                      Email
                    </span>
                  )}
                  {alert.notifications.webhook && (
                    <span className="px-2 py-1 bg-purple-100 dark:bg-purple-900 text-purple-700 dark:text-purple-300 text-xs rounded">
                      Webhook
                    </span>
                  )}
                  {alert.notifications.push && (
                    <span className="px-2 py-1 bg-green-100 dark:bg-green-900 text-green-700 dark:text-green-300 text-xs rounded">
                      Push
                    </span>
                  )}
                </div>
              </div>

              <div className="flex items-center space-x-2">
                <button
                  onClick={() => toggleAlertEnabled(alert.id)}
                  className={`p-2 rounded-md transition-colors ${
                    alert.enabled
                      ? 'text-green-600 hover:bg-green-100 dark:hover:bg-green-900'
                      : 'text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700'
                  }`}
                  title={alert.enabled ? 'Disable Alert' : 'Enable Alert'}
                >
                  {alert.enabled ? <Eye className="h-4 w-4" /> : <EyeOff className="h-4 w-4" />}
                </button>
                
                <button
                  onClick={() => editAlert(alert)}
                  className="p-2 text-blue-600 hover:bg-blue-100 dark:hover:bg-blue-900 rounded-md transition-colors"
                  title="Edit Alert"
                >
                  <Edit className="h-4 w-4" />
                </button>
                
                <button
                  onClick={() => deleteAlert(alert.id)}
                  className="p-2 text-red-600 hover:bg-red-100 dark:hover:bg-red-900 rounded-md transition-colors"
                  title="Delete Alert"
                >
                  <Trash2 className="h-4 w-4" />
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>

      {filteredAlerts.length === 0 && (
        <div className="text-center py-12">
          <Bell className="h-12 w-12 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
            No alert rules found
          </h3>
          <p className="text-gray-600 dark:text-gray-400">
            {searchQuery ? 'No alerts match your search criteria.' : 'Create your first alert rule to get started.'}
          </p>
        </div>
      )}

      {/* Create/Edit Modal would go here */}
      {isCreateModalOpen && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-md w-full m-4">
            <div className="p-6">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
                Create New Alert Rule
              </h3>
              <p className="text-gray-600 dark:text-gray-400">
                Alert creation form would be implemented here.
              </p>
              <div className="flex justify-end space-x-3 mt-6">
                <button
                  onClick={() => setIsCreateModalOpen(false)}
                  className="px-4 py-2 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-md transition-colors"
                >
                  Cancel
                </button>
                <button className="px-4 py-2 bg-primary-600 hover:bg-primary-700 text-white rounded-md transition-colors">
                  Create Alert
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AlertManagement;