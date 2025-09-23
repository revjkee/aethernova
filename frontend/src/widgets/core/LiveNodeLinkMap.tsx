import React, { useEffect, useRef, useState } from 'react';
import dynamic from 'next/dynamic';
import { useTranslation } from 'react-i18next';
import { getLiveNodeGraph } from '@/services/api/graphAPI';
import { Spinner } from '@/shared/components/Spinner';
import { Tooltip } from '@/shared/components/Tooltip';
import { AlertCircleIcon, WifiIcon, BotIcon, CpuIcon } from 'lucide-react';

const ForceGraph3D = dynamic(() => import('react-force-graph-3d'), { ssr: false });

interface Node {
  id: string;
  label: string;
  group: string;
  type: 'agent' | 'service' | 'module' | 'node' | 'warning';
  status: 'active' | 'inactive' | 'error';
}

interface Link {
  source: string;
  target: string;
  bandwidth: number;
}

interface GraphData {
  nodes: Node[];
  links: Link[];
}

const iconByType: Record<Node['type'], React.ReactNode> = {
  agent: <BotIcon size={14} />,
  service: <CpuIcon size={14} />,
  module: <WifiIcon size={14} />,
  warning: <AlertCircleIcon size={14} className="text-red-600" />,
  node: null,
};

const colorByStatus: Record<Node['status'], string> = {
  active: '#22c55e',
  inactive: '#9ca3af',
  error: '#ef4444',
};

const LiveNodeLinkMap: React.FC = () => {
  const { t } = useTranslation();
  const graphRef = useRef<any>(null);
  const [data, setData] = useState<GraphData>({ nodes: [], links: [] });
  const [loading, setLoading] = useState(true);

  const fetchGraphData = async () => {
    try {
      setLoading(true);
      const result = await getLiveNodeGraph();
      setData(result);
    } catch {
      setData({ nodes: [], links: [] });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchGraphData();
    const interval = setInterval(fetchGraphData, 30000); // обновлять каждые 30 сек
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (graphRef.current) {
      graphRef.current.zoomToFit(500, 50);
    }
  }, [data]);

  if (loading) {
    return (
      <div className="w-full h-full flex items-center justify-center">
        <Spinner size="lg" />
      </div>
    );
  }

  return (
    <div className="w-full h-[600px] rounded-lg border bg-zinc-900 shadow-md relative">
      <ForceGraph3D
        ref={graphRef}
        graphData={data}
        backgroundColor="rgba(24,24,27,1)"
        nodeAutoColorBy="group"
        nodeLabel={(node: Node) => `${node.label} (${node.status})`}
        nodeThreeObjectExtend
        nodeThreeObject={(node: Node) => {
          const sprite = document.createElement('div');
          sprite.style.padding = '4px 6px';
          sprite.style.borderRadius = '4px';
          sprite.style.background = colorByStatus[node.status];
          sprite.style.color = 'white';
          sprite.style.fontSize = '10px';
          sprite.innerText = node.label;
          return new window.THREE.CSS2DObject(sprite);
        }}
        linkWidth={(link: Link) => Math.max(1, link.bandwidth / 100)}
        linkDirectionalParticles={2}
        linkDirectionalParticleSpeed={d => 0.01 + (d.bandwidth || 1) * 0.0002}
        linkColor={() => '#64748b'}
      />
      <div className="absolute top-2 left-4 text-white text-xs bg-zinc-800 px-3 py-1 rounded shadow-sm">
        {t('graph.status.liveUpdate')} — {new Date().toLocaleTimeString()}
      </div>
    </div>
  );
};

export default React.memo(LiveNodeLinkMap);
