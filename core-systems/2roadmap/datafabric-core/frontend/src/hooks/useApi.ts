import { useState, useEffect } from 'react';
import { DashboardMetrics, DataSource, DataPipeline, SystemAlert } from '../types';

// Mock API delay
const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

// Mock data generators
const generateMockDashboardMetrics = (): DashboardMetrics => ({
  totalDataSources: 24,
  activeDataSources: 22,
  totalPipelines: 15,
  runningPipelines: 12,
  avgDataQuality: 98.5,
  totalAlerts: 3,
  unreadAlerts: 1,
  systemHealth: 'healthy',
  uptime: 99.97
});

const generateMockDataSources = (): DataSource[] => [
  {
    id: '1',
    name: 'Customer Database',
    type: 'database',
    status: 'connected',
    connection: { host: 'db.example.com', port: 5432, database: 'customers' },
    lastSync: new Date(Date.now() - 1000 * 60 * 5), // 5 minutes ago
    recordCount: 150000,
    schemaVersion: '2.1.0',
    createdAt: new Date('2024-01-15'),
    updatedAt: new Date()
  },
  {
    id: '2',
    name: 'Sales API',
    type: 'api',
    status: 'syncing',
    connection: { host: 'api.sales.com', protocol: 'https' },
    lastSync: new Date(Date.now() - 1000 * 60 * 15), // 15 minutes ago
    recordCount: 89000,
    schemaVersion: '1.5.2',
    createdAt: new Date('2024-02-01'),
    updatedAt: new Date()
  },
  {
    id: '3',
    name: 'Analytics Stream',
    type: 'stream',
    status: 'connected',
    connection: { host: 'kafka.analytics.com', port: 9092 },
    lastSync: new Date(Date.now() - 1000 * 30), // 30 seconds ago
    recordCount: 2500000,
    schemaVersion: '3.0.1',
    createdAt: new Date('2024-01-20'),
    updatedAt: new Date()
  }
];

const generateMockPipelines = (): DataPipeline[] => [
  {
    id: '1',
    name: 'Customer Data ETL',
    description: 'Extract, transform and load customer data from CRM to warehouse',
    sourceId: '1',
    targetId: 'warehouse-1',
    status: 'running',
    progress: 85,
    lastRun: new Date(Date.now() - 1000 * 60 * 10),
    nextRun: new Date(Date.now() + 1000 * 60 * 50),
    config: {
      schedule: '0 */2 * * *', // Every 2 hours
      transformations: ['normalize_phone', 'validate_email', 'geocode_address'],
      validators: ['email_format', 'required_fields']
    },
    metrics: {
      recordsProcessed: 145000,
      successRate: 99.2,
      avgProcessingTime: 1.5,
      errorCount: 12
    },
    createdAt: new Date('2024-01-15'),
    updatedAt: new Date()
  },
  {
    id: '2',
    name: 'Real-time Analytics',
    description: 'Stream processing for real-time business metrics',
    sourceId: '3',
    targetId: 'analytics-db',
    status: 'running',
    progress: 100,
    lastRun: new Date(Date.now() - 1000 * 60 * 2),
    config: {
      schedule: 'continuous',
      transformations: ['aggregate_events', 'calculate_metrics'],
      validators: ['data_quality_check']
    },
    metrics: {
      recordsProcessed: 2450000,
      successRate: 99.8,
      avgProcessingTime: 0.05,
      errorCount: 2
    },
    createdAt: new Date('2024-01-20'),
    updatedAt: new Date()
  }
];

const generateMockAlerts = (): SystemAlert[] => [
  {
    id: '1',
    type: 'warning',
    severity: 'medium',
    title: 'High Memory Usage',
    message: 'Data pipeline "Customer Data ETL" is using 85% of allocated memory',
    source: 'pipeline-monitor',
    timestamp: new Date(Date.now() - 1000 * 60 * 30),
    isRead: false,
    isResolved: false
  },
  {
    id: '2',
    type: 'info',
    severity: 'low',
    title: 'Scheduled Maintenance',
    message: 'System maintenance scheduled for tonight at 2:00 AM UTC',
    source: 'system',
    timestamp: new Date(Date.now() - 1000 * 60 * 60 * 2),
    isRead: true,
    isResolved: false
  },
  {
    id: '3',
    type: 'error',
    severity: 'high',
    title: 'Connection Failed',
    message: 'Unable to connect to data source "Legacy System DB"',
    source: 'connection-monitor',
    timestamp: new Date(Date.now() - 1000 * 60 * 60 * 6),
    isRead: true,
    isResolved: true,
    resolvedAt: new Date(Date.now() - 1000 * 60 * 60 * 4),
    resolvedBy: 'admin@example.com'
  }
];

// Custom hooks
export const useDashboardMetrics = () => {
  const [data, setData] = useState<DashboardMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true);
        await delay(500); // Simulate API call
        setData(generateMockDashboardMetrics());
      } catch (err) {
        setError('Failed to fetch dashboard metrics');
      } finally {
        setLoading(false);
      }
    };

    fetchData();
    
    // Auto-refresh every 30 seconds
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, []);

  return { data, loading, error, refetch: () => setLoading(true) };
};

export const useDataSources = () => {
  const [data, setData] = useState<DataSource[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true);
        await delay(300);
        setData(generateMockDataSources());
      } catch (err) {
        setError('Failed to fetch data sources');
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  return { data, loading, error };
};

export const useDataPipelines = () => {
  const [data, setData] = useState<DataPipeline[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true);
        await delay(400);
        setData(generateMockPipelines());
      } catch (err) {
        setError('Failed to fetch data pipelines');
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  return { data, loading, error };
};

export const useSystemAlerts = () => {
  const [data, setData] = useState<SystemAlert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true);
        await delay(200);
        setData(generateMockAlerts());
      } catch (err) {
        setError('Failed to fetch system alerts');
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  const markAsRead = (alertId: string) => {
    setData(prev => prev.map(alert => 
      alert.id === alertId ? { ...alert, isRead: true } : alert
    ));
  };

  const markAsResolved = (alertId: string) => {
    setData(prev => prev.map(alert => 
      alert.id === alertId 
        ? { ...alert, isResolved: true, resolvedAt: new Date(), resolvedBy: 'current-user' }
        : alert
    ));
  };

  return { data, loading, error, markAsRead, markAsResolved };
};