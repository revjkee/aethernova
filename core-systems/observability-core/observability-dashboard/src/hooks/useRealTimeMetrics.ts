import { useState, useEffect, useCallback } from 'react';
import { websocketService, MetricUpdate, AlertUpdate, SystemEvent } from '../services/websocketService';

export interface RealTimeMetrics {
  cpuUsage: number;
  memoryUsage: number;
  diskUsage: number;
  activeAgents: number;
  responseTime: number;
  errorRate: number;
  lastUpdate: number;
}

export interface RealtimeState {
  metrics: RealTimeMetrics;
  alerts: AlertUpdate[];
  systemEvents: SystemEvent[];
  connected: boolean;
  loading: boolean;
  error: string | null;
}

export const useRealTimeObservability = () => {
  const [state, setState] = useState<RealtimeState>({
    metrics: {
      cpuUsage: 0,
      memoryUsage: 0,
      diskUsage: 0,
      activeAgents: 0,
      responseTime: 0,
      errorRate: 0,
      lastUpdate: Date.now(),
    },
    alerts: [],
    systemEvents: [],
    connected: false,
    loading: true,
    error: null,
  });

  // Handle metric updates
  const handleMetricUpdate = useCallback((update: MetricUpdate) => {
    const metricKeys: Record<string, keyof RealTimeMetrics> = {
      cpu_usage: 'cpuUsage',
      memory_usage: 'memoryUsage',
      disk_usage: 'diskUsage',
      active_agents: 'activeAgents',
      response_time: 'responseTime',
      error_rate: 'errorRate',
    };
    const key = metricKeys[update.metric];
    if (!key) return;

    setState(prev => ({
      ...prev,
      metrics: {
        ...prev.metrics,
        [key]: update.value,
        lastUpdate: update.timestamp,
      }
    }));
  }, []);

  // Handle alert updates
  const handleAlertUpdate = useCallback((alert: AlertUpdate) => {
    setState(prev => ({
      ...prev,
      alerts: [alert, ...prev.alerts.slice(0, 49)] // Keep last 50 alerts
    }));
  }, []);

  // Handle system events
  const handleSystemEvent = useCallback((event: SystemEvent) => {
    setState(prev => ({
      ...prev,
      systemEvents: [event, ...prev.systemEvents.slice(0, 99)] // Keep last 100 events
    }));
  }, []);

  // Handle connection status
  const handleConnectionChange = useCallback((connected: boolean) => {
    setState(prev => ({
      ...prev,
      connected,
      loading: false,
      error: connected ? null : 'WebSocket connection lost'
    }));
  }, []);

  // Initialize WebSocket connection
  useEffect(() => {
    let mounted = true;

    const initWebSocket = async () => {
      try {
        // Subscribe to events
        const unsubscribeMetric = websocketService.onMetricUpdate(handleMetricUpdate);
        const unsubscribeAlert = websocketService.onAlertUpdate(handleAlertUpdate);
        const unsubscribeEvent = websocketService.onSystemEvent(handleSystemEvent);
        const unsubscribeConnection = websocketService.onConnectionChange(handleConnectionChange);

        // Connect
        await websocketService.connect();

        // Subscribe to specific metrics
        const metricsToSubscribe = [
          'cpu_usage',
          'memory_usage', 
          'disk_usage',
          'active_agents',
          'response_time',
          'error_rate'
        ];

        metricsToSubscribe.forEach(metric => {
          websocketService.subscribeToMetric(metric);
        });

        if (
          import.meta.env.DEV &&
          import.meta.env.VITE_ENABLE_MOCK_STREAM === 'true'
        ) {
          websocketService.startMockDataStream();
        }

        if (mounted) {
          setState(prev => ({ ...prev, loading: false, error: null }));
        }

        return () => {
          unsubscribeMetric();
          unsubscribeAlert();
          unsubscribeEvent();
          unsubscribeConnection();
        };
      } catch (error) {
        if (mounted) {
          setState(prev => ({
            ...prev,
            loading: false,
            error: error instanceof Error ? error.message : 'Failed to connect to WebSocket'
          }));
        }
      }
    };

    const cleanup = initWebSocket();

    return () => {
      mounted = false;
      cleanup.then(fn => fn && fn());
      websocketService.disconnect();
    };
  }, [handleMetricUpdate, handleAlertUpdate, handleSystemEvent, handleConnectionChange]);

  // Actions
  const acknowledgeAlert = useCallback((alertId: string) => {
    websocketService.acknowledgeAlert(alertId);
    setState(prev => ({
      ...prev,
      alerts: prev.alerts.map(alert => 
        alert.id === alertId ? { ...alert, resolved: true } : alert
      )
    }));
  }, []);

  const clearAlerts = useCallback(() => {
    setState(prev => ({
      ...prev,
      alerts: []
    }));
  }, []);

  const clearSystemEvents = useCallback(() => {
    setState(prev => ({
      ...prev,
      systemEvents: []
    }));
  }, []);

  const reconnect = useCallback(async () => {
    setState(prev => ({ ...prev, loading: true, error: null }));
    try {
      await websocketService.connect();
    } catch (error) {
      setState(prev => ({
        ...prev,
        loading: false,
        error: error instanceof Error ? error.message : 'Reconnection failed'
      }));
    }
  }, []);

  return {
    ...state,
    actions: {
      acknowledgeAlert,
      clearAlerts,
      clearSystemEvents,
      reconnect,
    }
  };
};

// Hook for historical metric data
export const useMetricHistory = (metricName: string, timeRange: { from: Date; to: Date }) => {
  const [data, setData] = useState<{ timestamp: number; value: number }[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const fromTimestamp = timeRange.from.getTime();
  const toTimestamp = timeRange.to.getTime();

  useEffect(() => {
    if (
      !metricName ||
      Number.isNaN(fromTimestamp) ||
      Number.isNaN(toTimestamp)
    ) return;

    setLoading(true);
    setError(null);

    // Request historical data
    websocketService.requestMetricHistory(metricName, {
      from: new Date(fromTimestamp),
      to: new Date(toTimestamp),
    });

    // Listen for historical data response
    const unsubscribe = websocketService.onMetricUpdate((update) => {
      if (update.metric === metricName) {
        setData(prev => [...prev, { timestamp: update.timestamp, value: update.value }].slice(-1000)); // Keep last 1000 points
      }
    });

    // Simulate loading completion
    const timeout = setTimeout(() => {
      setLoading(false);
    }, 1000);

    return () => {
      unsubscribe();
      clearTimeout(timeout);
    };
  }, [metricName, fromTimestamp, toTimestamp]);

  return { data, loading, error };
};

// Hook for connection status monitoring
export const useWebSocketStatus = () => {
  const [connected, setConnected] = useState(false);
  const [reconnectAttempts, setReconnectAttempts] = useState(0);

  useEffect(() => {
    const unsubscribe = websocketService.onConnectionChange((isConnected) => {
      setConnected(isConnected);
      if (isConnected) {
        setReconnectAttempts(0);
      } else {
        setReconnectAttempts(prev => prev + 1);
      }
    });

    // Check initial status
    setConnected(websocketService.getConnectionStatus());

    return unsubscribe;
  }, []);

  return { connected, reconnectAttempts };
};
