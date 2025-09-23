import React, { useEffect, useRef, useState } from 'react';
import cytoscape from 'cytoscape';
import dagre from 'cytoscape-dagre';
import { useSocket } from '@/shared/hooks/useSocket';
import { Spinner } from '@/shared/components/Spinner';
import './styles/AgentIntentGraph.css';

cytoscape.use(dagre);

type IntentNode = {
  id: string;
  label: string;
  type: 'goal' | 'subgoal' | 'action' | 'conflict' | 'ethics_violation';
  priority: number;
};

type IntentEdge = {
  source: string;
  target: string;
  label?: string;
};

interface GraphData {
  nodes: IntentNode[];
  edges: IntentEdge[];
}

interface AgentIntentGraphProps {
  agentId: string;
  height?: number;
}

export const AgentIntentGraph: React.FC<AgentIntentGraphProps> = ({
  agentId,
  height = 480,
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const [loading, setLoading] = useState(true);
  const cyRef = useRef<cytoscape.Core | null>(null);
  const { connect, disconnect } = useSocket(`/agents/${agentId}/intent_graph`);

  const getColorByType = (type: IntentNode['type']) => {
    switch (type) {
      case 'goal': return '#1976d2';
      case 'subgoal': return '#42a5f5';
      case 'action': return '#66bb6a';
      case 'conflict': return '#e53935';
      case 'ethics_violation': return '#8e24aa';
    }
  };

  const buildGraph = (data: GraphData) => {
    const elements = [
      ...data.nodes.map((n) => ({
        data: {
          id: n.id,
          label: n.label,
          priority: n.priority,
          type: n.type,
        },
      })),
      ...data.edges.map((e) => ({
        data: {
          id: `${e.source}-${e.target}`,
          source: e.source,
          target: e.target,
          label: e.label || '',
        },
      })),
    ];

    if (cyRef.current) {
      cyRef.current.destroy();
    }

    cyRef.current = cytoscape({
      container: containerRef.current!,
      elements,
      layout: {
        name: 'dagre',
        rankDir: 'TB',
        nodeSep: 50,
        edgeSep: 20,
        rankSep: 60,
      },
      style: [
        {
          selector: 'node',
          style: {
            label: 'data(label)',
            'background-color': (ele) => getColorByType(ele.data('type')),
            'border-width': 2,
            'border-color': '#000',
            'text-valign': 'center',
            'color': '#fff',
            'text-outline-width': 1,
            'text-outline-color': '#000',
            'font-size': 14,
            width: 60,
            height: 60,
          },
        },
        {
          selector: 'edge',
          style: {
            width: 2,
            'line-color': '#ccc',
            'target-arrow-color': '#ccc',
            'target-arrow-shape': 'triangle',
            label: 'data(label)',
            'font-size': 12,
            'text-background-opacity': 1,
            'text-background-color': '#fff',
            'text-background-shape': 'roundrectangle',
          },
        },
        {
          selector: ':selected',
          style: {
            'border-color': '#ffeb3b',
            'border-width': 4,
          },
        },
      ],
    });

    cyRef.current.ready(() => {
      cyRef.current?.fit();
    });
  };

  useEffect(() => {
    const socket = connect((event) => {
      const graph: GraphData = JSON.parse(event.data);
      buildGraph(graph);
      setLoading(false);
    });
    return () => disconnect(socket);
  }, [agentId]);

  return (
    <div className="agent-intent-graph-container" style={{ height }}>
      {loading ? (
        <Spinner size="medium" />
      ) : (
        <div ref={containerRef} className="agent-intent-graph" />
      )}
    </div>
  );
};
