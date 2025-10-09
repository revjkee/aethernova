// API hooks for Sentinel agent system

import { useState, useEffect, useCallback } from 'react';

// Types for Sentinel agents
export interface SentinelAgent {
  id: string;
  name: string;
  role: string;
  status: 'ACTIVE' | 'INACTIVE' | 'QUARANTINED' | 'ROGUE';
  lastSeen: string;
  threatsDetected: number;
  accuracy: number;
  location?: string;
  anomalyScore?: number;
}

export interface SentinelFilters {
  role: string;
  status: string;
  anomalyOnly: boolean;
  tactic: string;
}

export interface SentinelStream {
  logs: SentinelLog[];
  networkNodes: NetworkNode[];
  detectedThreats: DetectedThreat[];
}

export interface SentinelLog {
  id: string;
  timestamp: string;
  level: 'INFO' | 'WARN' | 'ERROR' | 'CRITICAL';
  message: string;
  agentId?: string;
  source: string;
}

export interface NetworkNode {
  id: string;
  name: string;
  type: 'agent' | 'server' | 'endpoint';
  status: 'online' | 'offline' | 'compromised';
  x: number;
  y: number;
}

export interface DetectedThreat {
  id: string;
  type: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  source: string;
  target: string;
  timestamp: string;
  mitigated: boolean;
}

// Mock data for development
const mockAgents: SentinelAgent[] = [
  {
    id: 'agent-001',
    name: 'Guardian Alpha',
    role: 'Network Monitor',
    status: 'ACTIVE',
    lastSeen: new Date().toISOString(),
    threatsDetected: 42,
    accuracy: 0.97,
    location: 'DMZ-1',
    anomalyScore: 0.23
  },
  {
    id: 'agent-002',
    name: 'Sentinel Beta',
    role: 'Intrusion Detection',
    status: 'ACTIVE',
    lastSeen: new Date(Date.now() - 60000).toISOString(),
    threatsDetected: 18,
    accuracy: 0.89,
    location: 'Core-Network',
    anomalyScore: 0.15
  },
  {
    id: 'agent-003',
    name: 'Watcher Gamma',
    role: 'Behavioral Analysis',
    status: 'QUARANTINED',
    lastSeen: new Date(Date.now() - 300000).toISOString(),
    threatsDetected: 7,
    accuracy: 0.76,
    location: 'Endpoint-Zone',
    anomalyScore: 0.84
  }
];

const mockLogs: SentinelLog[] = [
  {
    id: 'log-001',
    timestamp: new Date().toISOString(),
    level: 'INFO',
    message: 'Agent Guardian Alpha deployed successfully',
    agentId: 'agent-001',
    source: 'SentinelCore'
  },
  {
    id: 'log-002',
    timestamp: new Date(Date.now() - 30000).toISOString(),
    level: 'WARN',
    message: 'Anomalous network traffic detected from 192.168.1.45',
    agentId: 'agent-002',
    source: 'NetworkMonitor'
  },
  {
    id: 'log-003',
    timestamp: new Date(Date.now() - 60000).toISOString(),
    level: 'CRITICAL',
    message: 'Agent Watcher Gamma exhibiting rogue behavior - quarantined',
    agentId: 'agent-003',
    source: 'SentinelCore'
  }
];

// Hook for fetching sentinel agents
export const useSentinelAgentsQuery = (filters: SentinelFilters) => {
  const [data, setData] = useState<SentinelAgent[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refetch = useCallback(() => {
    setIsLoading(true);
    // Simulate API call
    setTimeout(() => {
      try {
        let filteredAgents = [...mockAgents];
        
        if (filters.status !== 'all') {
          filteredAgents = filteredAgents.filter(agent => 
            agent.status.toLowerCase() === filters.status.toLowerCase()
          );
        }
        
        if (filters.role !== 'all') {
          filteredAgents = filteredAgents.filter(agent => 
            agent.role.toLowerCase().includes(filters.role.toLowerCase())
          );
        }
        
        if (filters.anomalyOnly) {
          filteredAgents = filteredAgents.filter(agent => 
            (agent.anomalyScore || 0) > 0.5
          );
        }

        setData(filteredAgents);
        setError(null);
      } catch (err) {
        setError('Failed to fetch agents');
      } finally {
        setIsLoading(false);
      }
    }, 500);
  }, [filters]);

  useEffect(() => {
    refetch();
  }, [refetch]);

  return { data, isLoading, error, refetch };
};

// Hook for real-time sentinel stream
export const useSentinelStream = () => {
  const [stream, setStream] = useState<SentinelStream>({
    logs: [],
    networkNodes: [],
    detectedThreats: []
  });
  const [zkVerified, setZkVerified] = useState(false);
  const [isConnected, setIsConnected] = useState(false);

  const connect = useCallback(() => {
    setIsConnected(true);
    setZkVerified(true);
    
    // Initialize with mock data
    setStream({
      logs: mockLogs,
      networkNodes: [
        { id: 'node-1', name: 'Core Server', type: 'server', status: 'online', x: 50, y: 50 },
        { id: 'node-2', name: 'Agent Alpha', type: 'agent', status: 'online', x: 20, y: 30 },
        { id: 'node-3', name: 'Agent Beta', type: 'agent', status: 'online', x: 80, y: 70 },
        { id: 'node-4', name: 'Endpoint-1', type: 'endpoint', status: 'compromised', x: 10, y: 90 }
      ],
      detectedThreats: [
        {
          id: 'threat-1',
          type: 'Malware',
          severity: 'HIGH',
          source: 'External',
          target: 'Endpoint-1',
          timestamp: new Date().toISOString(),
          mitigated: false
        }
      ]
    });

    // Simulate real-time updates
    const interval = setInterval(() => {
      if (Math.random() > 0.7) {
        const newLog: SentinelLog = {
          id: `log-${Date.now()}`,
          timestamp: new Date().toISOString(),
          level: ['INFO', 'WARN', 'ERROR'][Math.floor(Math.random() * 3)] as any,
          message: `System event detected at ${new Date().toLocaleTimeString()}`,
          source: 'SentinelCore'
        };
        
        setStream(prev => ({
          ...prev,
          logs: [newLog, ...prev.logs].slice(0, 50) // Keep last 50 logs
        }));
      }
    }, 3000);

    return () => clearInterval(interval);
  }, []);

  const disconnect = useCallback(() => {
    setIsConnected(false);
    setZkVerified(false);
  }, []);

  return { stream, zkVerified, isConnected, connect, disconnect };
};