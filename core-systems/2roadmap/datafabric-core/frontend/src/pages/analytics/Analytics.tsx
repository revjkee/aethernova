import React, { useState } from 'react';
import { 
  ChartBarIcon,
  PresentationChartLineIcon,
  ChartPieIcon,
  TableCellsIcon,
  FunnelIcon,
  CalendarIcon,
  ArrowDownTrayIcon
} from '@heroicons/react/24/outline';

const Analytics: React.FC = () => {
  const [selectedTimeRange, setSelectedTimeRange] = useState('7d');
  const [selectedMetric, setSelectedMetric] = useState('volume');

  const metrics = [
    {
      name: 'Data Volume',
      value: '2.4 TB',
      growth: '+12.5%',
      icon: ChartBarIcon,
      color: 'blue'
    },
    {
      name: 'Pipeline Runs',
      value: '1,247',
      growth: '+8.2%',
      icon: PresentationChartLineIcon,
      color: 'green'
    },
    {
      name: 'Quality Score',
      value: '94.8%',
      growth: '+2.1%',
      icon: ChartPieIcon,
      color: 'purple'
    },
    {
      name: 'Active Sources',
      value: '47',
      growth: '+15.3%',
      icon: TableCellsIcon,
      color: 'orange'
    }
  ];

  const timeRanges = [
    { value: '1d', label: '1 Day' },
    { value: '7d', label: '7 Days' },
    { value: '30d', label: '30 Days' },
    { value: '90d', label: '90 Days' }
  ];

  const getColorClasses = (color: string) => {
    const colors = {
      blue: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
      green: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
      purple: 'bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200',
      orange: 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200'
    };
    return colors[color as keyof typeof colors] || colors.blue;
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
          Analytics & Insights
        </h1>
        <div className="flex items-center space-x-3">
          <button className="bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 px-4 py-2 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
            <ArrowDownTrayIcon className="h-4 w-4 inline mr-2" />
            Export
          </button>
          <button className="bg-primary-600 text-white px-4 py-2 rounded-lg hover:bg-primary-700 transition-colors">
            Create Report
          </button>
        </div>
      </div>

      {/* Controls */}
      <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 p-6">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between space-y-4 lg:space-y-0">
          <div className="flex items-center space-x-4">
            <div className="flex items-center space-x-2">
              <CalendarIcon className="h-5 w-5 text-gray-400" />
              <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Time Range:</span>
              <select
                value={selectedTimeRange}
                onChange={(e) => setSelectedTimeRange(e.target.value)}
                className="border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white px-3 py-1 text-sm focus:ring-2 focus:ring-primary-500 focus:border-transparent"
              >
                {timeRanges.map((range) => (
                  <option key={range.value} value={range.value}>
                    {range.label}
                  </option>
                ))}
              </select>
            </div>
            <div className="flex items-center space-x-2">
              <FunnelIcon className="h-5 w-5 text-gray-400" />
              <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Metric:</span>
              <select
                value={selectedMetric}
                onChange={(e) => setSelectedMetric(e.target.value)}
                className="border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white px-3 py-1 text-sm focus:ring-2 focus:ring-primary-500 focus:border-transparent"
              >
                <option value="volume">Data Volume</option>
                <option value="quality">Data Quality</option>
                <option value="performance">Performance</option>
                <option value="usage">Usage</option>
              </select>
            </div>
          </div>
        </div>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {metrics.map((metric) => (
          <div
            key={metric.name}
            className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 p-6"
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center">
                <div className={`p-2 rounded-lg ${getColorClasses(metric.color)}`}>
                  <metric.icon className="h-6 w-6" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-600 dark:text-gray-400">
                    {metric.name}
                  </p>
                  <p className="text-2xl font-bold text-gray-900 dark:text-white">
                    {metric.value}
                  </p>
                </div>
              </div>
              <span className="text-sm font-medium text-green-600 dark:text-green-400">
                {metric.growth}
              </span>
            </div>
          </div>
        ))}
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Data Volume Trend */}
        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              Data Volume Trend
            </h3>
            <ChartBarIcon className="h-5 w-5 text-gray-400" />
          </div>
          <div className="h-64 flex items-center justify-center bg-gray-50 dark:bg-gray-700 rounded-lg">
            <div className="text-center">
              <ChartBarIcon className="h-12 w-12 text-gray-400 mx-auto mb-2" />
              <p className="text-gray-500 dark:text-gray-400">Chart will be rendered here</p>
            </div>
          </div>
        </div>

        {/* Quality Score Distribution */}
        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              Quality Score Distribution
            </h3>
            <ChartPieIcon className="h-5 w-5 text-gray-400" />
          </div>
          <div className="h-64 flex items-center justify-center bg-gray-50 dark:bg-gray-700 rounded-lg">
            <div className="text-center">
              <ChartPieIcon className="h-12 w-12 text-gray-400 mx-auto mb-2" />
              <p className="text-gray-500 dark:text-gray-400">Chart will be rendered here</p>
            </div>
          </div>
        </div>

        {/* Pipeline Performance */}
        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              Pipeline Performance
            </h3>
            <PresentationChartLineIcon className="h-5 w-5 text-gray-400" />
          </div>
          <div className="h-64 flex items-center justify-center bg-gray-50 dark:bg-gray-700 rounded-lg">
            <div className="text-center">
              <PresentationChartLineIcon className="h-12 w-12 text-gray-400 mx-auto mb-2" />
              <p className="text-gray-500 dark:text-gray-400">Chart will be rendered here</p>
            </div>
          </div>
        </div>

        {/* Data Source Usage */}
        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              Data Source Usage
            </h3>
            <TableCellsIcon className="h-5 w-5 text-gray-400" />
          </div>
          <div className="space-y-4">
            {[
              { name: 'CRM Database', usage: 85, color: 'bg-blue-500' },
              { name: 'Sales API', usage: 72, color: 'bg-green-500' },
              { name: 'Web Analytics', usage: 58, color: 'bg-purple-500' },
              { name: 'File Storage', usage: 34, color: 'bg-orange-500' }
            ].map((source, index) => (
              <div key={index} className="flex items-center">
                <div className="flex-1">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
                      {source.name}
                    </span>
                    <span className="text-sm text-gray-500 dark:text-gray-400">
                      {source.usage}%
                    </span>
                  </div>
                  <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                    <div
                      className={`h-2 rounded-full ${source.color}`}
                      style={{ width: `${source.usage}%` }}
                    />
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Insights and Recommendations */}
      <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 p-6">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          Insights & Recommendations
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="space-y-4">
            <div className="p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg border border-blue-200 dark:border-blue-800">
              <h4 className="font-medium text-blue-900 dark:text-blue-200 mb-2">
                🔍 Data Quality Improvement
              </h4>
              <p className="text-sm text-blue-700 dark:text-blue-300">
                Data quality scores have improved by 2.1% this week. Consider implementing 
                automated validation rules for the remaining low-quality datasets.
              </p>
            </div>
            <div className="p-4 bg-green-50 dark:bg-green-900/20 rounded-lg border border-green-200 dark:border-green-800">
              <h4 className="font-medium text-green-900 dark:text-green-200 mb-2">
                📈 Performance Optimization
              </h4>
              <p className="text-sm text-green-700 dark:text-green-300">
                Pipeline execution time has decreased by 15% after recent optimizations. 
                Consider applying similar techniques to other pipelines.
              </p>
            </div>
          </div>
          <div className="space-y-4">
            <div className="p-4 bg-orange-50 dark:bg-orange-900/20 rounded-lg border border-orange-200 dark:border-orange-800">
              <h4 className="font-medium text-orange-900 dark:text-orange-200 mb-2">
                ⚠️ Capacity Planning
              </h4>
              <p className="text-sm text-orange-700 dark:text-orange-300">
                Data volume is growing at 12.5% weekly. Consider scaling infrastructure 
                to accommodate the increased load.
              </p>
            </div>
            <div className="p-4 bg-purple-50 dark:bg-purple-900/20 rounded-lg border border-purple-200 dark:border-purple-800">
              <h4 className="font-medium text-purple-900 dark:text-purple-200 mb-2">
                🎯 Usage Patterns
              </h4>
              <p className="text-sm text-purple-700 dark:text-purple-300">
                CRM Database shows highest usage (85%). Consider creating cached views 
                for frequently accessed data to improve performance.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Analytics;