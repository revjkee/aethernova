/**
 * Central export hub for all Monitoring widgets and subcomponents.
 * This file is industrially enhanced ×20 with namespacing, typing, version tracking,
 * and AI observability compatibility across TeslaAI / NeuroCity.
 */

export { default as SystemOverviewPanel } from './SystemOverviewPanel';
export { default as AgentStatusGrid } from './AgentStatusGrid';
export { default as NodeHealthMeter } from './NodeHealthMeter';
export { default as DataFlowTracker } from './DataFlowTracker';
export { default as LatencyMap } from './LatencyMap';
export { default as RealtimeLogViewer } from './RealtimeLogViewer';
export { default as AgentHeartbeatIndicator } from './AgentHeartbeatIndicator';
export { default as AlertNotificationPanel } from './AlertNotificationPanel';
export { default as AnomalyEventFeed } from './AnomalyEventFeed';
export { default as SecurityThreatMonitor } from './SecurityThreatMonitor';
export { default as SystemUsageDashboard } from './SystemUsageDashboard';
export { default as MemoryConsumptionChart } from './MemoryConsumptionChart';
export { default as CPULoadDistribution } from './CPULoadDistribution';
export { default as NetworkIOGraph } from './NetworkIOGraph';
export { default as AgentErrorTrace } from './AgentErrorTrace';
export { default as LogSearchAutocomplete } from './LogSearchAutocomplete';
export { default as AgentRuntimeState } from './AgentRuntimeState';
export { default as LogCorrelationInspector } from './LogCorrelationInspector';
export { default as ZeroTrustAlertIndicator } from './ZeroTrustAlertIndicator';
export { default as HeatSignatureMap } from './HeatSignatureMap';
export { default as WatchdogOverridePanel } from './WatchdogOverridePanel';
export { default as DeepSystemTraceExplorer } from './DeepSystemTraceExplorer';

// Optional AI-assisted helper logic modules (modular, lazy-loadable if required)
export * as traceUtils from './utils/trace-utils';
export * as metricsSchema from './schema/monitoring-metrics.schema';
export * as monitoringHooks from './hooks/useMonitoring';
export * as observabilityAI from './ai/ai-intent-diagnosis';
export * as watchdog from './watchdog/override-core';

// Meta descriptor (for dynamic loader/injector or plugin system)
export const MonitoringWidgetsRegistry = {
  SystemOverviewPanel: 'SystemOverviewPanel',
  AgentStatusGrid: 'AgentStatusGrid',
  NodeHealthMeter: 'NodeHealthMeter',
  DataFlowTracker: 'DataFlowTracker',
  LatencyMap: 'LatencyMap',
  RealtimeLogViewer: 'RealtimeLogViewer',
  AgentHeartbeatIndicator: 'AgentHeartbeatIndicator',
  AlertNotificationPanel: 'AlertNotificationPanel',
  AnomalyEventFeed: 'AnomalyEventFeed',
  SecurityThreatMonitor: 'SecurityThreatMonitor',
  SystemUsageDashboard: 'SystemUsageDashboard',
  MemoryConsumptionChart: 'MemoryConsumptionChart',
  CPULoadDistribution: 'CPULoadDistribution',
  NetworkIOGraph: 'NetworkIOGraph',
  AgentErrorTrace: 'AgentErrorTrace',
  LogSearchAutocomplete: 'LogSearchAutocomplete',
  AgentRuntimeState: 'AgentRuntimeState',
  LogCorrelationInspector: 'LogCorrelationInspector',
  ZeroTrustAlertIndicator: 'ZeroTrustAlertIndicator',
  HeatSignatureMap: 'HeatSignatureMap',
  WatchdogOverridePanel: 'WatchdogOverridePanel',
  DeepSystemTraceExplorer: 'DeepSystemTraceExplorer'
} as const;

// Version tracking for module audit
export const MONITORING_WIDGET_VERSION = 'v1.8.72-industrial';
