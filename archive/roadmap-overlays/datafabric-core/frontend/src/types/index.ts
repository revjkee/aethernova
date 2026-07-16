// Core data types for DataFabric
export interface DataSource {
  id: string;
  name: string;
  type: 'database' | 'api' | 'file' | 'stream' | 'cloud';
  status: 'connected' | 'disconnected' | 'error' | 'syncing';
  connection: {
    host?: string;
    port?: number;
    database?: string;
    protocol?: string;
  };
  lastSync: Date;
  recordCount: number;
  schemaVersion: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface DataPipeline {
  id: string;
  name: string;
  description: string;
  sourceId: string;
  targetId: string;
  status: 'running' | 'stopped' | 'error' | 'paused';
  progress: number;
  lastRun: Date;
  nextRun?: Date;
  config: {
    schedule: string;
    transformations: string[];
    validators: string[];
  };
  metrics: {
    recordsProcessed: number;
    successRate: number;
    avgProcessingTime: number;
    errorCount: number;
  };
  createdAt: Date;
  updatedAt: Date;
}

export interface DataQualityMetric {
  id: string;
  sourceId: string;
  metric: 'completeness' | 'accuracy' | 'consistency' | 'timeliness' | 'validity';
  value: number;
  threshold: number;
  status: 'pass' | 'warning' | 'fail';
  lastChecked: Date;
  trend: 'improving' | 'stable' | 'declining';
}

export interface SystemAlert {
  id: string;
  type: 'error' | 'warning' | 'info';
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  message: string;
  source: string;
  timestamp: Date;
  isRead: boolean;
  isResolved: boolean;
  resolvedAt?: Date;
  resolvedBy?: string;
}

export interface DashboardMetrics {
  totalDataSources: number;
  activeDataSources: number;
  totalPipelines: number;
  runningPipelines: number;
  avgDataQuality: number;
  totalAlerts: number;
  unreadAlerts: number;
  systemHealth: 'healthy' | 'warning' | 'critical';
  uptime: number;
}

export interface User {
  id: string;
  email: string;
  name: string;
  role: 'admin' | 'analyst' | 'viewer';
  permissions: string[];
  lastLogin: Date;
  isActive: boolean;
}

// API Response types
export interface ApiResponse<T> {
  data: T;
  success: boolean;
  message?: string;
  timestamp: Date;
}

export interface PaginatedResponse<T> {
  data: T[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
}

// Filter and search types
export interface FilterOptions {
  status?: string[];
  type?: string[];
  dateRange?: {
    start: Date;
    end: Date;
  };
  search?: string;
}

export interface SortOptions {
  field: string;
  direction: 'asc' | 'desc';
}