import React, { useState } from 'react';
import { 
  ShieldCheckIcon,
  UserGroupIcon,
  KeyIcon,
  DocumentTextIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  ClockIcon,
  EyeIcon,
  PencilIcon,
  TrashIcon
} from '@heroicons/react/24/outline';

interface GovernanceRule {
  id: string;
  name: string;
  type: 'access' | 'retention' | 'classification' | 'quality';
  status: 'active' | 'inactive' | 'pending';
  severity: 'high' | 'medium' | 'low';
  description: string;
  lastUpdated: string;
  violations: number;
}

interface DataClassification {
  id: string;
  level: string;
  count: number;
  description: string;
  color: string;
}

const Governance: React.FC = () => {
  const [selectedTab, setSelectedTab] = useState('policies');

  const governanceRules: GovernanceRule[] = [
    {
      id: '1',
      name: 'PII Data Access Control',
      type: 'access',
      status: 'active',
      severity: 'high',
      description: 'Restricts access to personally identifiable information based on user roles',
      lastUpdated: '2024-01-15',
      violations: 0
    },
    {
      id: '2',
      name: 'Data Retention Policy',
      type: 'retention',
      status: 'active',
      severity: 'medium',
      description: 'Automatically archives data older than 7 years according to compliance requirements',
      lastUpdated: '2024-01-10',
      violations: 2
    },
    {
      id: '3',
      name: 'Data Quality Validation',
      type: 'quality',
      status: 'active',
      severity: 'high',
      description: 'Ensures data completeness and accuracy before processing',
      lastUpdated: '2024-01-12',
      violations: 1
    },
    {
      id: '4',
      name: 'Sensitive Data Classification',
      type: 'classification',
      status: 'pending',
      severity: 'high',
      description: 'Automatically classifies and tags sensitive data elements',
      lastUpdated: '2024-01-08',
      violations: 0
    }
  ];

  const dataClassifications: DataClassification[] = [
    { id: '1', level: 'Public', count: 145, description: 'Data that can be freely shared', color: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200' },
    { id: '2', level: 'Internal', count: 89, description: 'Data for internal use only', color: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200' },
    { id: '3', level: 'Confidential', count: 34, description: 'Sensitive business data', color: 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200' },
    { id: '4', level: 'Restricted', count: 12, description: 'Highly sensitive regulated data', color: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200' }
  ];

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'active':
        return <CheckCircleIcon className="h-5 w-5 text-green-500" />;
      case 'inactive':
        return <ExclamationTriangleIcon className="h-5 w-5 text-red-500" />;
      case 'pending':
        return <ClockIcon className="h-5 w-5 text-yellow-500" />;
      default:
        return <ClockIcon className="h-5 w-5 text-gray-500" />;
    }
  };

  const getStatusBadge = (status: string) => {
    const baseClasses = "inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium";
    switch (status) {
      case 'active':
        return `${baseClasses} bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200`;
      case 'inactive':
        return `${baseClasses} bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200`;
      case 'pending':
        return `${baseClasses} bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200`;
      default:
        return `${baseClasses} bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200`;
    }
  };

  const getSeverityBadge = (severity: string) => {
    const baseClasses = "inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium";
    switch (severity) {
      case 'high':
        return `${baseClasses} bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200`;
      case 'medium':
        return `${baseClasses} bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200`;
      case 'low':
        return `${baseClasses} bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200`;
      default:
        return `${baseClasses} bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200`;
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'access':
        return <KeyIcon className="h-5 w-5" />;
      case 'retention':
        return <ClockIcon className="h-5 w-5" />;
      case 'classification':
        return <DocumentTextIcon className="h-5 w-5" />;
      case 'quality':
        return <CheckCircleIcon className="h-5 w-5" />;
      default:
        return <ShieldCheckIcon className="h-5 w-5" />;
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
          Data Governance
        </h1>
        <button className="bg-primary-600 text-white px-4 py-2 rounded-lg hover:bg-primary-700 transition-colors">
          Create Policy
        </button>
      </div>

      {/* Overview Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center">
            <div className="p-2 bg-green-100 dark:bg-green-900 rounded-lg">
              <ShieldCheckIcon className="h-6 w-6 text-green-600 dark:text-green-400" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Active Policies</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {governanceRules.filter(r => r.status === 'active').length}
              </p>
            </div>
          </div>
        </div>
        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center">
            <div className="p-2 bg-red-100 dark:bg-red-900 rounded-lg">
              <ExclamationTriangleIcon className="h-6 w-6 text-red-600 dark:text-red-400" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Violations</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {governanceRules.reduce((sum, r) => sum + r.violations, 0)}
              </p>
            </div>
          </div>
        </div>
        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center">
            <div className="p-2 bg-blue-100 dark:bg-blue-900 rounded-lg">
              <DocumentTextIcon className="h-6 w-6 text-blue-600 dark:text-blue-400" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Classified Assets</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {dataClassifications.reduce((sum, c) => sum + c.count, 0)}
              </p>
            </div>
          </div>
        </div>
        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center">
            <div className="p-2 bg-purple-100 dark:bg-purple-900 rounded-lg">
              <UserGroupIcon className="h-6 w-6 text-purple-600 dark:text-purple-400" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Compliance Score</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">96%</p>
            </div>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700">
        <div className="border-b border-gray-200 dark:border-gray-700">
          <nav className="flex space-x-8 px-6">
            {[
              { id: 'policies', name: 'Policies & Rules', icon: ShieldCheckIcon },
              { id: 'classification', name: 'Data Classification', icon: DocumentTextIcon },
              { id: 'access', name: 'Access Control', icon: KeyIcon },
              { id: 'audit', name: 'Audit Log', icon: ClockIcon }
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setSelectedTab(tab.id)}
                className={`flex items-center py-4 px-1 border-b-2 font-medium text-sm ${
                  selectedTab === tab.id
                    ? 'border-primary-500 text-primary-600 dark:text-primary-400'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-300'
                }`}
              >
                <tab.icon className="h-5 w-5 mr-2" />
                {tab.name}
              </button>
            ))}
          </nav>
        </div>

        <div className="p-6">
          {selectedTab === 'policies' && (
            <div className="space-y-4">
              {governanceRules.map((rule) => (
                <div
                  key={rule.id}
                  className="border border-gray-200 dark:border-gray-600 rounded-lg p-4 hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-start space-x-3">
                      <div className="p-2 bg-gray-100 dark:bg-gray-700 rounded-lg">
                        {getTypeIcon(rule.type)}
                      </div>
                      <div className="flex-1">
                        <div className="flex items-center space-x-2 mb-2">
                          <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                            {rule.name}
                          </h3>
                          {getStatusIcon(rule.status)}
                          <span className={getStatusBadge(rule.status)}>
                            {rule.status.charAt(0).toUpperCase() + rule.status.slice(1)}
                          </span>
                          <span className={getSeverityBadge(rule.severity)}>
                            {rule.severity.charAt(0).toUpperCase() + rule.severity.slice(1)}
                          </span>
                        </div>
                        <p className="text-gray-600 dark:text-gray-300 mb-2">
                          {rule.description}
                        </p>
                        <div className="flex items-center space-x-4 text-sm text-gray-500 dark:text-gray-400">
                          <span>Last updated: {rule.lastUpdated}</span>
                          <span>Violations: {rule.violations}</span>
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      <button className="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300">
                        <EyeIcon className="h-4 w-4" />
                      </button>
                      <button className="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300">
                        <PencilIcon className="h-4 w-4" />
                      </button>
                      <button className="p-2 text-gray-400 hover:text-red-600 dark:hover:text-red-400">
                        <TrashIcon className="h-4 w-4" />
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}

          {selectedTab === 'classification' && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                {dataClassifications.map((classification) => (
                  <div
                    key={classification.id}
                    className="bg-gray-50 dark:bg-gray-700 rounded-lg p-4"
                  >
                    <div className="flex items-center justify-between mb-2">
                      <span className={`px-3 py-1 rounded-full text-sm font-medium ${classification.color}`}>
                        {classification.level}
                      </span>
                      <span className="text-2xl font-bold text-gray-900 dark:text-white">
                        {classification.count}
                      </span>
                    </div>
                    <p className="text-sm text-gray-600 dark:text-gray-300">
                      {classification.description}
                    </p>
                  </div>
                ))}
              </div>
              
              {/* Classification Distribution Chart */}
              <div className="bg-gray-50 dark:bg-gray-700 rounded-lg p-8">
                <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
                  Classification Distribution
                </h3>
                <div className="h-64 flex items-center justify-center">
                  <div className="text-center">
                    <DocumentTextIcon className="h-12 w-12 text-gray-400 mx-auto mb-2" />
                    <p className="text-gray-500 dark:text-gray-400">Classification chart will be rendered here</p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {selectedTab === 'access' && (
            <div className="text-center py-12">
              <KeyIcon className="h-12 w-12 text-gray-400 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
                Access Control Management
              </h3>
              <p className="text-gray-500 dark:text-gray-400 mb-4">
                Manage user permissions and access policies for data assets
              </p>
              <button className="bg-primary-600 text-white px-4 py-2 rounded-lg hover:bg-primary-700 transition-colors">
                Configure Access Controls
              </button>
            </div>
          )}

          {selectedTab === 'audit' && (
            <div className="text-center py-12">
              <ClockIcon className="h-12 w-12 text-gray-400 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
                Audit Trail
              </h3>
              <p className="text-gray-500 dark:text-gray-400 mb-4">
                Track all data access and modification activities
              </p>
              <button className="bg-primary-600 text-white px-4 py-2 rounded-lg hover:bg-primary-700 transition-colors">
                View Audit Logs
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Governance;