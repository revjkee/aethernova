// Sentinel Network Map Component

import React, { useMemo } from 'react';
import { NetworkNode, DetectedThreat } from '../sentinelAPI';

interface SentinelNetworkMapProps {
  nodes: NetworkNode[];
  threats: DetectedThreat[];
}

export const SentinelNetworkMap: React.FC<SentinelNetworkMapProps> = ({ 
  nodes, 
  threats 
}) => {
  const mapData = useMemo(() => {
    // Create connections between nodes
    const connections = [];
    for (let i = 0; i < nodes.length - 1; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const node1 = nodes[i];
        const node2 = nodes[j];
        
        // Create connection if nodes are related or within range
        if (Math.random() > 0.5) { // Simplified connection logic
          connections.push({
            from: node1,
            to: node2,
            hasActivity: threats.some(t => 
              (t.source === node1.name || t.target === node1.name) &&
              (t.source === node2.name || t.target === node2.name)
            )
          });
        }
      }
    }
    
    return { nodes, connections, threats };
  }, [nodes, threats]);

  const getNodeColor = (node: NetworkNode) => {
    switch (node.status) {
      case 'online':
        return node.type === 'agent' ? 'fill-green-500' : 'fill-blue-500';
      case 'offline':
        return 'fill-gray-400';
      case 'compromised':
        return 'fill-red-500';
      default:
        return 'fill-gray-400';
    }
  };

  const getNodeIcon = (node: NetworkNode) => {
    switch (node.type) {
      case 'agent':
        return (
          <g>
            <circle cx="12" cy="12" r="10" className={getNodeColor(node)} />
            <circle cx="12" cy="12" r="6" fill="white" />
            <circle cx="12" cy="12" r="3" className={getNodeColor(node)} />
          </g>
        );
      case 'server':
        return (
          <g>
            <rect x="4" y="6" width="16" height="12" rx="2" className={getNodeColor(node)} />
            <rect x="6" y="8" width="12" height="2" fill="white" />
            <rect x="6" y="12" width="12" height="2" fill="white" />
          </g>
        );
      case 'endpoint':
        return (
          <g>
            <rect x="6" y="4" width="12" height="14" rx="2" className={getNodeColor(node)} />
            <rect x="8" y="6" width="8" height="6" fill="white" />
            <circle cx="12" cy="15" r="1" fill="white" />
          </g>
        );
      default:
        return <circle cx="12" cy="12" r="8" className={getNodeColor(node)} />;
    }
  };

  const getThreatPosition = (threat: DetectedThreat) => {
    const sourceNode = mapData.nodes.find(n => n.name === threat.source);
    const targetNode = mapData.nodes.find(n => n.name === threat.target);
    
    if (sourceNode && targetNode) {
      return {
        x: (sourceNode.x + targetNode.x) / 2,
        y: (sourceNode.y + targetNode.y) / 2
      };
    }
    
    return { x: 50, y: 50 };
  };

  const getSeverityColor = (severity: DetectedThreat['severity']) => {
    switch (severity) {
      case 'LOW': return 'fill-yellow-400';
      case 'MEDIUM': return 'fill-orange-500';
      case 'HIGH': return 'fill-red-500';
      case 'CRITICAL': return 'fill-red-700';
      default: return 'fill-gray-400';
    }
  };

  return (
    <div className="relative bg-gray-50 dark:bg-zinc-800 rounded-lg p-4 h-64 overflow-hidden">
      {/* Network Visualization */}
      <svg
        viewBox="0 0 100 100"
        className="w-full h-full"
        preserveAspectRatio="xMidYMid meet"
      >
        {/* Grid Background */}
        <defs>
          <pattern
            id="grid"
            width="10"
            height="10"
            patternUnits="userSpaceOnUse"
          >
            <path
              d="M 10 0 L 0 0 0 10"
              fill="none"
              stroke="currentColor"
              strokeWidth="0.5"
              className="text-gray-300 dark:text-zinc-600"
            />
          </pattern>
        </defs>
        <rect width="100" height="100" fill="url(#grid)" />

        {/* Connections */}
        {mapData.connections.map((connection, index) => (
          <line
            key={`connection-${index}`}
            x1={connection.from.x}
            y1={connection.from.y}
            x2={connection.to.x}
            y2={connection.to.y}
            stroke="currentColor"
            strokeWidth={connection.hasActivity ? "2" : "1"}
            className={
              connection.hasActivity 
                ? "text-red-500 animate-pulse" 
                : "text-gray-400 dark:text-zinc-600"
            }
            strokeDasharray={connection.hasActivity ? "5,5" : "none"}
          />
        ))}

        {/* Threat Indicators */}
        {mapData.threats.map((threat) => {
          const position = getThreatPosition(threat);
          return (
            <g key={threat.id}>
              <circle
                cx={position.x}
                cy={position.y}
                r="3"
                className={getSeverityColor(threat.severity)}
              />
              <circle
                cx={position.x}
                cy={position.y}
                r="5"
                fill="none"
                stroke="currentColor"
                strokeWidth="1"
                className="text-red-500 animate-ping"
              />
            </g>
          );
        })}

        {/* Nodes */}
        {mapData.nodes.map((node) => (
          <g key={node.id}>
            <svg
              x={node.x - 12}
              y={node.y - 12}
              width="24"
              height="24"
              viewBox="0 0 24 24"
            >
              {getNodeIcon(node)}
            </svg>
            
            {/* Node Label */}
            <text
              x={node.x}
              y={node.y + 20}
              textAnchor="middle"
              className="fill-current text-xs text-gray-700 dark:text-gray-300"
              fontSize="3"
            >
              {node.name}
            </text>
            
            {/* Status Indicator */}
            <circle
              cx={node.x + 8}
              cy={node.y - 8}
              r="2"
              className={node.status === 'online' ? 'fill-green-400' : 
                        node.status === 'compromised' ? 'fill-red-500' : 'fill-gray-400'}
            />
          </g>
        ))}
      </svg>

      {/* Legend */}
      <div className="absolute bottom-2 right-2 bg-white dark:bg-zinc-900 rounded p-2 shadow-sm border border-gray-200 dark:border-zinc-700">
        <div className="text-xs space-y-1">
          <div className="font-semibold text-gray-700 dark:text-gray-300 mb-2">Легенда</div>
          
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 bg-green-500 rounded-full" />
            <span className="text-gray-600 dark:text-gray-400">Онлайн</span>
          </div>
          
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 bg-red-500 rounded-full" />
            <span className="text-gray-600 dark:text-gray-400">Компрометирован</span>
          </div>
          
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 bg-gray-400 rounded-full" />
            <span className="text-gray-600 dark:text-gray-400">Оффлайн</span>
          </div>
          
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 bg-red-500 rounded-full animate-pulse" />
            <span className="text-gray-600 dark:text-gray-400">Угроза</span>
          </div>
        </div>
      </div>

      {/* Stats Overlay */}
      <div className="absolute top-2 left-2 bg-white dark:bg-zinc-900 rounded p-2 shadow-sm border border-gray-200 dark:border-zinc-700">
        <div className="text-xs space-y-1">
          <div className="font-semibold text-gray-700 dark:text-gray-300">Статистика сети</div>
          <div className="text-gray-600 dark:text-gray-400">Узлы: {mapData.nodes.length}</div>
          <div className="text-gray-600 dark:text-gray-400">Угрозы: {mapData.threats.length}</div>
          <div className="text-gray-600 dark:text-gray-400">
            Компрометированы: {mapData.nodes.filter(n => n.status === 'compromised').length}
          </div>
        </div>
      </div>
    </div>
  );
};