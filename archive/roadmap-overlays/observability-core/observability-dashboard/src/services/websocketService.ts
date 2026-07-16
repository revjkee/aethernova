import { io, Socket } from 'socket.io-client';

export interface MetricUpdate {
  timestamp: number;
  metric: string;
  value: number;
  labels?: Record<string, string>;
}

export interface AlertUpdate {
  id: string;
  level: 'info' | 'warning' | 'error' | 'critical';
  message: string;
  timestamp: number;
  source: string;
  resolved?: boolean;
}

export interface SystemEvent {
  type: 'agent_restart' | 'service_down' | 'service_up' | 'high_load' | 'disk_full';
  timestamp: number;
  message: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  data?: any;
}

class WebSocketService {
  private socket: Socket | null = null;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectInterval = 5000;
  private isConnected = false;

  // Event listeners
  private metricListeners: ((update: MetricUpdate) => void)[] = [];
  private alertListeners: ((alert: AlertUpdate) => void)[] = [];
  private systemEventListeners: ((event: SystemEvent) => void)[] = [];
  private connectionListeners: ((connected: boolean) => void)[] = [];

  constructor(private serverUrl: string = 'ws://localhost:8080') {}

  connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      try {
        this.socket = io(this.serverUrl, {
          transports: ['websocket', 'polling'],
          timeout: 10000,
          reconnection: true,
          reconnectionAttempts: this.maxReconnectAttempts,
          reconnectionDelay: this.reconnectInterval,
        });

        this.socket.on('connect', () => {
          console.log('WebSocket connected to observability server');
          this.isConnected = true;
          this.reconnectAttempts = 0;
          this.notifyConnectionListeners(true);
          resolve();
        });

        this.socket.on('disconnect', (reason) => {
          console.log('WebSocket disconnected:', reason);
          this.isConnected = false;
          this.notifyConnectionListeners(false);
        });

        this.socket.on('connect_error', (error) => {
          console.error('WebSocket connection error:', error);
          this.isConnected = false;
          this.notifyConnectionListeners(false);
          
          if (this.reconnectAttempts >= this.maxReconnectAttempts) {
            reject(new Error('Failed to connect after maximum attempts'));
          }
        });

        // Metric updates
        this.socket.on('metric_update', (update: MetricUpdate) => {
          this.metricListeners.forEach(listener => listener(update));
        });

        // Alert updates
        this.socket.on('alert_update', (alert: AlertUpdate) => {
          this.alertListeners.forEach(listener => listener(alert));
        });

        // System events
        this.socket.on('system_event', (event: SystemEvent) => {
          this.systemEventListeners.forEach(listener => listener(event));
        });

        // Health check
        this.socket.on('ping', () => {
          this.socket?.emit('pong');
        });

      } catch (error) {
        reject(error);
      }
    });
  }

  disconnect(): void {
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
      this.isConnected = false;
      this.notifyConnectionListeners(false);
    }
  }

  // Subscription methods
  onMetricUpdate(listener: (update: MetricUpdate) => void): () => void {
    this.metricListeners.push(listener);
    return () => {
      const index = this.metricListeners.indexOf(listener);
      if (index > -1) {
        this.metricListeners.splice(index, 1);
      }
    };
  }

  onAlertUpdate(listener: (alert: AlertUpdate) => void): () => void {
    this.alertListeners.push(listener);
    return () => {
      const index = this.alertListeners.indexOf(listener);
      if (index > -1) {
        this.alertListeners.splice(index, 1);
      }
    };
  }

  onSystemEvent(listener: (event: SystemEvent) => void): () => void {
    this.systemEventListeners.push(listener);
    return () => {
      const index = this.systemEventListeners.indexOf(listener);
      if (index > -1) {
        this.systemEventListeners.splice(index, 1);
      }
    };
  }

  onConnectionChange(listener: (connected: boolean) => void): () => void {
    this.connectionListeners.push(listener);
    return () => {
      const index = this.connectionListeners.indexOf(listener);
      if (index > -1) {
        this.connectionListeners.splice(index, 1);
      }
    };
  }

  // Send methods
  subscribeToMetric(metricName: string): void {
    if (this.socket && this.isConnected) {
      this.socket.emit('subscribe_metric', { metric: metricName });
    }
  }

  unsubscribeFromMetric(metricName: string): void {
    if (this.socket && this.isConnected) {
      this.socket.emit('unsubscribe_metric', { metric: metricName });
    }
  }

  acknowledgeAlert(alertId: string): void {
    if (this.socket && this.isConnected) {
      this.socket.emit('acknowledge_alert', { alertId });
    }
  }

  requestMetricHistory(metricName: string, timeRange: { from: Date; to: Date }): void {
    if (this.socket && this.isConnected) {
      this.socket.emit('request_metric_history', {
        metric: metricName,
        from: timeRange.from.toISOString(),
        to: timeRange.to.toISOString(),
      });
    }
  }

  // Utility methods
  private notifyConnectionListeners(connected: boolean): void {
    this.connectionListeners.forEach(listener => listener(connected));
  }

  getConnectionStatus(): boolean {
    return this.isConnected;
  }

  // Mock data generator for development
  startMockDataStream(): void {
    if (!this.socket) return;

    // Simulate metric updates
    const metricInterval = setInterval(() => {
      if (!this.isConnected) {
        clearInterval(metricInterval);
        return;
      }

      const mockMetrics: MetricUpdate[] = [
        {
          timestamp: Date.now(),
          metric: 'cpu_usage',
          value: Math.random() * 100,
          labels: { instance: 'aethernova-node-1' }
        },
        {
          timestamp: Date.now(),
          metric: 'memory_usage',
          value: Math.random() * 100,
          labels: { instance: 'aethernova-node-1' }
        },
        {
          timestamp: Date.now(),
          metric: 'active_agents',
          value: 315 + Math.floor(Math.random() * 10 - 5),
          labels: { system: 'aethernova' }
        },
        {
          timestamp: Date.now(),
          metric: 'response_time',
          value: 30 + Math.random() * 40,
          labels: { service: 'api' }
        }
      ];

      mockMetrics.forEach(metric => {
        this.metricListeners.forEach(listener => listener(metric));
      });
    }, 2000);

    // Simulate random alerts
    const alertInterval = setInterval(() => {
      if (!this.isConnected) {
        clearInterval(alertInterval);
        return;
      }

      if (Math.random() < 0.1) { // 10% chance every 10 seconds
        const mockAlert: AlertUpdate = {
          id: `alert_${Date.now()}`,
          level: ['info', 'warning', 'error'][Math.floor(Math.random() * 3)] as any,
          message: [
            'High CPU usage detected on node-1',
            'Agent restart completed successfully', 
            'New deployment detected',
            'Memory usage above threshold'
          ][Math.floor(Math.random() * 4)],
          timestamp: Date.now(),
          source: 'system-monitor'
        };

        this.alertListeners.forEach(listener => listener(mockAlert));
      }
    }, 10000);
  }
}

// Singleton instance
export const websocketService = new WebSocketService();
export default WebSocketService;