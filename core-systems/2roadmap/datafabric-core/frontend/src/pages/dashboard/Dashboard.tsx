import React from 'react';
import { 
  ChartBarIcon,
  CircleStackIcon,
  CpuChipIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  ClockIcon
} from '@heroicons/react/24/outline';

const Dashboard: React.FC = () => {
  const stats = [
    {
      name: 'Active Data Sources',
      value: '24',
      change: '+4.75%',
      changeType: 'positive',
      icon: CircleStackIcon,
    },
    {
      name: 'Running Pipelines',
      value: '12',
      change: '+54.02%',
      changeType: 'positive',
      icon: CpuChipIcon,
    },
    {
      name: 'Data Quality Score',
      value: '98.5%',
      change: '+2.1%',
      changeType: 'positive',
      icon: CheckCircleIcon,
    },
    {
      name: 'Active Alerts',
      value: '3',
      change: '-10.1%',
      changeType: 'negative',
      icon: ExclamationTriangleIcon,
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
          DataFabric Dashboard
        </h1>
        <div className="flex items-center space-x-3">
          <button className="bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 px-4 py-2 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
            Export
          </button>
          <button className="bg-primary-600 text-white px-4 py-2 rounded-lg hover:bg-primary-700 transition-colors">
            Refresh
          </button>
        </div>
      </div>

      {/* Stats Overview */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {stats.map((stat) => (
          <div
            key={stat.name}
            className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 p-6"
          >
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <stat.icon className="h-8 w-8 text-primary-600" />
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">
                    {stat.name}
                  </dt>
                  <dd className="flex items-baseline">
                    <div className="text-2xl font-semibold text-gray-900 dark:text-white">
                      {stat.value}
                    </div>
                    <div
                      className={`ml-2 flex items-baseline text-sm font-semibold ${
                        stat.changeType === 'positive'
                          ? 'text-green-600'
                          : 'text-red-600'
                      }`}
                    >
                      {stat.change}
                    </div>
                  </dd>
                </dl>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6">
        {/* System Health */}
        <div className="xl:col-span-2">
          <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                System Health
              </h3>
              <ChartBarIcon className="h-5 w-5 text-gray-400" />
            </div>
            <div className="text-center py-12">
              <div className="w-24 h-24 mx-auto bg-green-100 dark:bg-green-900 rounded-full flex items-center justify-center mb-4">
                <CheckCircleIcon className="h-12 w-12 text-green-600 dark:text-green-400" />
              </div>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">All Systems Operational</p>
              <p className="text-gray-500 dark:text-gray-400">Last updated: 2 minutes ago</p>
            </div>
          </div>
        </div>
        
        {/* Recent Activity */}
        <div>
          <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                Recent Activity
              </h3>
              <ClockIcon className="h-5 w-5 text-gray-400" />
            </div>
            <div className="space-y-4">
              {[
                { action: 'Pipeline "User Analytics" completed', time: '2 min ago', status: 'success' },
                { action: 'Data source "CRM DB" connected', time: '5 min ago', status: 'success' },
                { action: 'Quality check failed for "Orders"', time: '12 min ago', status: 'error' },
                { action: 'New dataset "Customer Segments" added', time: '1 hour ago', status: 'info' },
              ].map((activity, index) => (
                <div key={index} className="flex items-start">
                  <div className={`w-2 h-2 rounded-full mt-2 mr-3 ${
                    activity.status === 'success' ? 'bg-green-400' :
                    activity.status === 'error' ? 'bg-red-400' : 'bg-blue-400'
                  }`} />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm text-gray-900 dark:text-white">{activity.action}</p>
                    <p className="text-xs text-gray-500 dark:text-gray-400">{activity.time}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;