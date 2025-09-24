import React, { useEffect, useRef, useState } from 'react';
import dynamic from 'next/dynamic';
import { fetchAgentNetwork } from '@/shared/api/agentAPI';
import { AgentNode, AgentLink } from '@/shared/types/agents';
import { Spinner } from '@/shared/components/Spinner';
import { useTheme } from '@/shared/hooks/useTheme';
import { Badge } from '@/components/ui/badge';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { IconShield, IconUser, IconZap } from 'lucide-react';

const ForceGraph2D = dynamic(() => import('react-force-graph').then(mod => mod.ForceGraph2D), { ssr: false });

interface AgentNetworkData {
  nodes: AgentNode[];
  links: AgentLink[];
}

export const AgentNetworkMap: React.FC = () => {
  const [graphData, setGraphData] = useState<AgentNetworkData>({ nodes: [], links: [] });
  const [loading, setLoading] = useState(true);
  const fgRef = useRef<any>(null);
  const { isDark } = useTheme();

  useEffect(() => {
    const loadData = async () => {
      try {
        const data = await fetchAgentNetwork();
        setGraphData(data);
      } catch (e) {
        console.error('Ошибка загрузки сети агентов', e);
      } finally {
        setLoading(false);
      }
    };

    loadData();
  }, []);

  const getNodeColor = (node: AgentNode) => {
    if (node.status === 'anomaly') return '#e11d48';
    if (node.status === 'idle') return '#94a3b8';
    if (node.status === 'active') return '#22c55e';
    return '#0ea5e9';
  };

  const getNodeTooltip = (node: AgentNode) => {
    return (
      <div className="p-2 text-sm">
        <div><strong>ID:</strong> {node.id}</div>
        <div><strong>Имя:</strong> {node.name}</div>
        <div><strong>Роль:</strong> {node.role}</div>
        <div><strong>Состояние:</strong> {node.status}</div>
        <div><strong>Intent:</strong> {node.intent ?? '—'}</div>
      </div>
    );
  };

  if (loading) return <Spinner label="Загрузка сетевого графа агентов..." />;

  return (
    <div className="relative h-[720px] w-full rounded-xl border bg-background shadow-md">
      <ForceGraph2D
        ref={fgRef}
        graphData={graphData}
        nodeId="id"
        nodeLabel={(node: any) => node.name}
        linkDirectionalParticles={1}
        linkDirectionalParticleWidth={2}
        linkColor={() => isDark ? 'rgba(255,255,255,0.2)' : 'rgba(0,0,0,0.2)'}
        nodeCanvasObject={(node: any, ctx, globalScale) => {
          const label = node.name;
          const fontSize = 12 / globalScale;
          ctx.font = `${fontSize}px Inter`;
          ctx.fillStyle = getNodeColor(node);
          ctx.beginPath();
          ctx.arc(node.x, node.y, 6, 0, 2 * Math.PI, false);
          ctx.fill();
          ctx.fillStyle = isDark ? '#ffffff' : '#000000';
          ctx.fillText(label, node.x + 10, node.y + 4);
        }}
        onNodeClick={(node: any) => {
          if (fgRef.current) {
            fgRef.current.centerAt(node.x, node.y, 1000);
            fgRef.current.zoom(3, 2000);
          }
        }}
      />

      <div className="absolute top-2 left-2 flex gap-2 z-10">
        <Tooltip>
          <TooltipTrigger asChild>
            <Badge variant="outline"><IconZap size={14} className="mr-1" /> active</Badge>
          </TooltipTrigger>
          <TooltipContent>Активные агенты</TooltipContent>
        </Tooltip>
        <Tooltip>
          <TooltipTrigger asChild>
            <Badge variant="outline"><IconUser size={14} className="mr-1" /> idle</Badge>
          </TooltipTrigger>
          <TooltipContent>Неактивные агенты</TooltipContent>
        </Tooltip>
        <Tooltip>
          <TooltipTrigger asChild>
            <Badge variant="destructive"><IconShield size={14} className="mr-1" /> anomaly</Badge>
          </TooltipTrigger>
          <TooltipContent>Выявлены аномалии</TooltipContent>
        </Tooltip>
      </div>
    </div>
  );
};
