export interface ApiResponse<T = any> {
  success: boolean;
  data: T;
  message?: string;
  errors?: Record<string, string[]>;
  meta?: {
    pagination?: {
      page: number;
      limit: number;
      total: number;
      totalPages: number;
    };
    filters?: Record<string, any>;
    sorting?: {
      field: string;
      direction: 'asc' | 'desc';
    };
  };
}

export interface DataSource {
  id: string;
  name: string;
  type: 'database' | 'api' | 'file' | 'stream' | 'cloud';
  status: 'active' | 'inactive' | 'error' | 'connecting';
  config: Record<string, any>;
  metadata: {
    createdAt: string;
    updatedAt: string;
    createdBy: string;
    tags: string[];
    description?: string;
  };
  metrics: {
    totalRecords: number;
    lastSyncAt: string;
    avgResponseTime: number;
    errorRate: number;
  };
}

export interface DataPipeline {
  id: string;
  name: string;
  description?: string;
  status: 'running' | 'stopped' | 'error' | 'pending';
  source: DataSource;
  targets: DataSource[];
  transformations: Transformation[];
  schedule: {
    type: 'cron' | 'interval' | 'event';
    expression: string;
    timezone?: string;
  };
  metrics: {
    totalRuns: number;
    successRate: number;
    avgDuration: number;
    lastRunAt: string;
    nextRunAt?: string;
  };
  createdAt: string;
  updatedAt: string;
}

export interface Transformation {
  id: string;
  type: 'map' | 'filter' | 'aggregate' | 'join' | 'custom';
  config: Record<string, any>;
  order: number;
}

export interface Dataset {
  id: string;
  name: string;
  description?: string;
  schema: DataSchema;
  source: DataSource;
  tags: string[];
  quality: {
    score: number;
    issues: QualityIssue[];
    lastCheckedAt: string;
  };
  usage: {
    accessCount: number;
    lastAccessedAt: string;
    popularQueries: string[];
  };
}

export interface DataSchema {
  fields: SchemaField[];
  primaryKeys: string[];
  foreignKeys: ForeignKey[];
  indexes: Index[];
}

export interface SchemaField {
  name: string;
  type: string;
  nullable: boolean;
  description?: string;
  constraints?: Record<string, any>;
  statistics?: {
    nullCount: number;
    uniqueCount: number;
    minValue?: any;
    maxValue?: any;
    avgValue?: any;
  };
}

export interface QualityIssue {
  field: string;
  type: 'missing' | 'invalid' | 'duplicate' | 'outlier';
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  count: number;
}

export interface ForeignKey {
  field: string;
  referencedTable: string;
  referencedField: string;
}

export interface Index {
  name: string;
  fields: string[];
  type: 'primary' | 'unique' | 'regular' | 'fulltext';
}