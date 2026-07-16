import { useState, useEffect } from 'react';
import PrometheusService from '../services/prometheusService';

const prometheusService = new PrometheusService();

export interface SystemMetrics {
  cpuUsage: number;
  memoryUsage: number;
  diskUsage: number;
  networkIn: number;
  networkOut: number;
}

export interface AetherNovaMetrics {
  activeAgents: number;
  totalRequests: number;
  responseTime: number;
  errorRate: number;
  alertsCount: number;
}

export const useSystemMetrics = (refreshInterval: number = 30000) => {
  const [metrics, setMetrics] = useState<SystemMetrics>({
    cpuUsage: 0,
    memoryUsage: 0,
    diskUsage: 0,
    networkIn: 0,
    networkOut: 0,
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchMetrics = async () => {
      try {
        setLoading(true);
        const data = await prometheusService.getSystemMetrics();
        setMetrics(data);
        setError(null);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to fetch system metrics');
      } finally {
        setLoading(false);
      }
    };

    fetchMetrics();
    const interval = setInterval(fetchMetrics, refreshInterval);

    return () => clearInterval(interval);
  }, [refreshInterval]);

  return { metrics, loading, error };
};

export const useAetherNovaMetrics = (refreshInterval: number = 30000) => {
  const [metrics, setMetrics] = useState<AetherNovaMetrics>({
    activeAgents: 315,
    totalRequests: 0,
    responseTime: 45,
    errorRate: 0,
    alertsCount: 3,
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchMetrics = async () => {
      try {
        setLoading(true);
        const data = await prometheusService.getAetherNovaMetrics();
        setMetrics(data);
        setError(null);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to fetch AetherNova metrics');
      } finally {
        setLoading(false);
      }
    };

    fetchMetrics();
    const interval = setInterval(fetchMetrics, refreshInterval);

    return () => clearInterval(interval);
  }, [refreshInterval]);

  return { metrics, loading, error };
};

export const usePrometheusQuery = (query: string, refreshInterval: number = 30000) => {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!query) return;

    const fetchData = async () => {
      try {
        setLoading(true);
        const response = await prometheusService.query(query);
        if (response.status === 'success') {
          setData(response.data);
          setError(null);
        } else {
          setError(response.error || 'Query failed');
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to execute query');
      } finally {
        setLoading(false);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, refreshInterval);

    return () => clearInterval(interval);
  }, [query, refreshInterval]);

  return { data, loading, error };
};