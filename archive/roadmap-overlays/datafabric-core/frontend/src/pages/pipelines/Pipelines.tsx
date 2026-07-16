import React, { useState } from 'react';
import { 
  PlayIcon,
  PauseIcon,
  StopIcon,
  AdjustmentsHorizontalIcon,
  EyeIcon,
  ChartBarIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  ClockIcon,
  CpuChipIcon,
  ArrowPathIcon
} from '@heroicons/react/24/outline';

interface Pipeline {
  id: string;
  name: string;
  status: 'running' | 'paused' | 'stopped' | 'error' | 'completed';
  type: string;
  source: string;
  destination: string;
  lastRun: string;
  nextRun?: string;
  duration: string;
  recordsProcessed: number;
  errorRate: number;
  description: string;
}

const Pipelines: React.FC = () => {
  const [selectedStatus, setSelectedStatus] = useState('all');

  const pipelines: Pipeline[] = [
    {
      id: '1',
      name: 'Customer Data Sync',
      status: 'running',
      type: 'ETL',
      source: 'CRM Database',
      destination: 'Data Warehouse',
      lastRun: '2024-01-15 14:30',
      nextRun: '2024-01-15 18:30',
      duration: '45 min',
      recordsProcessed: 125000,
      errorRate: 0.2,
      description: 'Synchronizes customer data from CRM to data warehouse every 4 hours'
    },
    {
      id: '2',
      name: 'Sales Analytics Pipeline',
      status: 'completed',
      type: 'ELT',
      source: 'Sales API',
      destination: 'Analytics DB',
      lastRun: '2024-01-15 12:00',
      nextRun: '2024-01-16 12:00',
      duration: '1h 20m',
      recordsProcessed: 89000,
      errorRate: 0.0,
      description: 'Daily processing of sales data for analytics and reporting'
    },
    {
      id: '3',
      name: 'Real-time Events',
      status: 'running',
      type: 'Stream',
      source: 'Kafka Topic',
      destination: 'Event Store',
      lastRun: 'Continuous',
      duration: 'N/A',
      recordsProcessed: 1200000,
      errorRate: 1.2,
      description: 'Real-time processing of user events and behavioral data'
    },
    {
      id: '4',
      name: 'Data Quality Check',
      status: 'error',
      type: 'Validation',
      source: 'Data Warehouse',
      destination: 'Quality Reports',
      lastRun: '2024-01-15 10:00',
      nextRun: '2024-01-15 16:00',
      duration: '25 min',
      recordsProcessed: 45000,
      errorRate: 15.8,
      description: 'Automated data quality validation and anomaly detection'
    }
  ];

  const filteredPipelines = pipelines.filter(pipeline => {
    return selectedStatus === 'all' || pipeline.status === selectedStatus;
  });

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'running':
        return <PlayIcon className="h-5 w-5 text-green-500" />;
      case 'paused':
        return <PauseIcon className="h-5 w-5 text-yellow-500" />;
      case 'stopped':
        return <StopIcon className="h-5 w-5 text-gray-500" />;
      case 'error':
        return <ExclamationTriangleIcon className="h-5 w-5 text-red-500" />;
      case 'completed':
        return <CheckCircleIcon className="h-5 w-5 text-blue-500" />;
      default:
        return <ClockIcon className="h-5 w-5 text-gray-500" />;
    }
  };

  const getStatusBadge = (status: string) => {
    const baseClasses = "inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium";
    switch (status) {
      case 'running':
        return `${baseClasses} bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200`;
      case 'paused':
        return `${baseClasses} bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200`;
      case 'stopped':
        return `${baseClasses} bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200`;
      case 'error':
        return `${baseClasses} bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200`;
      case 'completed':
        return `${baseClasses} bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200`;
      default:
        return `${baseClasses} bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200`;
    }
  };

  const getErrorRateColor = (errorRate: number) => {
    if (errorRate === 0) return 'text-green-600 dark:text-green-400';
    if (errorRate < 5) return 'text-yellow-600 dark:text-yellow-400';
    return 'text-red-600 dark:text-red-400';
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
          Data Pipelines
        </h1>
        <div className="flex items-center space-x-3">
          <button className="bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 px-4 py-2 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
            <ArrowPathIcon className="h-4 w-4 inline mr-2" />
            Refresh
          </button>
          <button className="bg-primary-600 text-white px-4 py-2 rounded-lg hover:bg-primary-700 transition-colors">
            Create Pipeline
          </button>
        </div>
      </div>

      {/* Status Filter */}
      <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 p-6">
        <div className="flex items-center space-x-4">
          <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Filter by status:</span>
          <div className="flex space-x-2">
            {['all', 'running', 'completed', 'paused', 'error', 'stopped'].map((status) => (
              <button
                key={status}
                onClick={() => setSelectedStatus(status)}
                className={`px-3 py-1 rounded-full text-sm font-medium transition-colors ${
                  selectedStatus === status
                    ? 'bg-primary-600 text-white'
                    : 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600'
                }`}
              >
                {status.charAt(0).toUpperCase() + status.slice(1)}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Pipelines Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {filteredPipelines.map((pipeline) => (
          <div 
            key={pipeline.id}
            className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 p-6"
          >
            {/* Header */}
            <div className="flex items-start justify-between mb-4">
              <div className="flex items-center space-x-3">
                {getStatusIcon(pipeline.status)}
                <div>
                  <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                    {pipeline.name}
                  </h3>
                  <p className="text-sm text-gray-500 dark:text-gray-400">
                    {pipeline.type} Pipeline
                  </p>
                </div>
              </div>
              <span className={getStatusBadge(pipeline.status)}>
                {pipeline.status.charAt(0).toUpperCase() + pipeline.status.slice(1)}
              </span>
            </div>

            {/* Description */}
            <p className="text-sm text-gray-600 dark:text-gray-300 mb-4">
              {pipeline.description}
            </p>

            {/* Data Flow */}
            <div className="bg-gray-50 dark:bg-gray-700 rounded-lg p-4 mb-4">
              <div className="flex items-center justify-between text-sm">
                <div className="flex-1">
                  <span className="font-medium text-gray-700 dark:text-gray-300">Source:</span>
                  <p className="text-gray-900 dark:text-white">{pipeline.source}</p>
                </div>
                <div className="px-4">
                  <ArrowPathIcon className="h-5 w-5 text-gray-400" />
                </div>
                <div className="flex-1 text-right">
                  <span className="font-medium text-gray-700 dark:text-gray-300">Destination:</span>
                  <p className="text-gray-900 dark:text-white">{pipeline.destination}</p>
                </div>
              </div>
            </div>

            {/* Metrics */}
            <div className="grid grid-cols-2 gap-4 mb-4">
              <div>
                <span className="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Records Processed
                </span>
                <p className="text-lg font-semibold text-gray-900 dark:text-white">
                  {pipeline.recordsProcessed.toLocaleString()}
                </p>
              </div>
              <div>
                <span className="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Error Rate
                </span>
                <p className={`text-lg font-semibold ${getErrorRateColor(pipeline.errorRate)}`}>
                  {pipeline.errorRate}%
                </p>
              </div>
              <div>
                <span className="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Duration
                </span>
                <p className="text-lg font-semibold text-gray-900 dark:text-white">
                  {pipeline.duration}
                </p>
              </div>
              <div>
                <span className="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Last Run
                </span>
                <p className="text-lg font-semibold text-gray-900 dark:text-white">
                  {pipeline.lastRun}
                </p>
              </div>
            </div>

            {/* Next Run */}
            {pipeline.nextRun && (
              <div className="mb-4">
                <span className="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Next Run
                </span>
                <p className="text-sm text-gray-900 dark:text-white">
                  {pipeline.nextRun}
                </p>
              </div>
            )}

            {/* Actions */}
            <div className="flex items-center justify-between pt-4 border-t border-gray-200 dark:border-gray-700">
              <div className="flex items-center space-x-2">
                {pipeline.status === 'running' ? (
                  <button className="p-2 text-yellow-600 hover:text-yellow-700 dark:text-yellow-400 dark:hover:text-yellow-300">
                    <PauseIcon className="h-4 w-4" />
                  </button>
                ) : (
                  <button className="p-2 text-green-600 hover:text-green-700 dark:text-green-400 dark:hover:text-green-300">
                    <PlayIcon className="h-4 w-4" />
                  </button>
                )}
                <button className="p-2 text-gray-600 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300">
                  <StopIcon className="h-4 w-4" />
                </button>
                <button className="p-2 text-gray-600 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300">
                  <AdjustmentsHorizontalIcon className="h-4 w-4" />
                </button>
              </div>
              <div className="flex items-center space-x-2">
                <button className="p-2 text-gray-600 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300">
                  <ChartBarIcon className="h-4 w-4" />
                </button>
                <button className="p-2 text-primary-600 hover:text-primary-700 dark:text-primary-400 dark:hover:text-primary-300">
                  <EyeIcon className="h-4 w-4" />
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Pipeline Performance Summary */}
      <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 p-6">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          Performance Summary
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <div className="text-center">
            <div className="flex items-center justify-center w-12 h-12 bg-green-100 dark:bg-green-900 rounded-lg mx-auto mb-2">
              <CpuChipIcon className="h-6 w-6 text-green-600 dark:text-green-400" />
            </div>
            <p className="text-2xl font-bold text-gray-900 dark:text-white">
              {pipelines.filter(p => p.status === 'running').length}
            </p>
            <p className="text-sm text-gray-500 dark:text-gray-400">Running</p>
          </div>
          <div className="text-center">
            <div className="flex items-center justify-center w-12 h-12 bg-blue-100 dark:bg-blue-900 rounded-lg mx-auto mb-2">
              <CheckCircleIcon className="h-6 w-6 text-blue-600 dark:text-blue-400" />
            </div>
            <p className="text-2xl font-bold text-gray-900 dark:text-white">
              {pipelines.filter(p => p.status === 'completed').length}
            </p>
            <p className="text-sm text-gray-500 dark:text-gray-400">Completed</p>
          </div>
          <div className="text-center">
            <div className="flex items-center justify-center w-12 h-12 bg-red-100 dark:bg-red-900 rounded-lg mx-auto mb-2">
              <ExclamationTriangleIcon className="h-6 w-6 text-red-600 dark:text-red-400" />
            </div>
            <p className="text-2xl font-bold text-gray-900 dark:text-white">
              {pipelines.filter(p => p.status === 'error').length}
            </p>
            <p className="text-sm text-gray-500 dark:text-gray-400">Errors</p>
          </div>
          <div className="text-center">
            <div className="flex items-center justify-center w-12 h-12 bg-purple-100 dark:bg-purple-900 rounded-lg mx-auto mb-2">
              <ArrowPathIcon className="h-6 w-6 text-purple-600 dark:text-purple-400" />
            </div>
            <p className="text-2xl font-bold text-gray-900 dark:text-white">
              {pipelines.reduce((sum, p) => sum + p.recordsProcessed, 0).toLocaleString()}
            </p>
            <p className="text-sm text-gray-500 dark:text-gray-400">Total Records</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Pipelines;