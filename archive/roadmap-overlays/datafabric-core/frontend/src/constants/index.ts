export const API_ENDPOINTS = {
  DATASOURCES: '/api/datafabric/sources',
  PIPELINES: '/api/datafabric/pipelines',
  DATASETS: '/api/datafabric/datasets',
  CATALOG: '/api/catalog/search',
  ANALYTICS: '/api/analytics',
  GOVERNANCE: '/api/governance',
  QUALITY: '/api/quality',
  LINEAGE: '/api/lineage',
} as const;

export const WEBSOCKET_EVENTS = {
  PIPELINE_STATUS: 'pipeline:status',
  DATA_QUALITY: 'quality:update',
  SYSTEM_HEALTH: 'system:health',
  ALERTS: 'alerts:new',
} as const;

export const DATA_SOURCE_TYPES = {
  DATABASE: 'database',
  API: 'api',
  FILE: 'file', 
  STREAM: 'stream',
  CLOUD: 'cloud',
} as const;

export const PIPELINE_STATUS = {
  RUNNING: 'running',
  STOPPED: 'stopped',
  ERROR: 'error',
  PENDING: 'pending',
} as const;

export const QUALITY_THRESHOLDS = {
  EXCELLENT: 95,
  GOOD: 80,
  FAIR: 60,
  POOR: 0,
} as const;

export const ROUTES = {
  DASHBOARD: '/',
  CATALOG: '/catalog',
  PIPELINES: '/pipelines',
  ANALYTICS: '/analytics',
  GOVERNANCE: '/governance',
  SETTINGS: '/settings',
} as const;
