// src/widgets/Security/AttackSurfaceMap.tsx
import React, { useEffect, useRef, useState } from "react";
import ForceGraph2D, { ForceGraphMethods } from "react-force-graph-2d";
import { Card, CardHeader, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { AlertCircle, ShieldCheck, AlertTriangle } from "lucide-react";
import { useAttackSurfaceStore } from "@/hooks/security/useAttackSurfaceStore";
import { useTheme } from "next-themes";
import { cn } from "@/lib/utils";

interface Node {
  id: string;
  name: string;
  risk: "low" | "medium" | "high" | "critical";
  group: number;
  metadata?: Record<string, any>;
}

interface Link {
  source: string;
  target: string;
  type?: string;
  risk?: string;
}

export const AttackSurfaceMap: React.FC = () => {
  const fgRef = useRef<ForceGraphMethods>();
  const { theme } = useTheme();
  const { nodes, links, fetchTopology, alertingMap } = useAttackSurfaceStore();
  const [highlightedNode, setHighlightedNode] = useState<Node | null>(null);

  useEffect(() => {
    fetchTopology();
  }, [fetchTopology]);

  const getNodeColor = (risk: string): string => {
    switch (risk) {
      case "critical":
        return "#ff0033";
      case "high":
        return "#ff8800";
      case "medium":
        return "#ffaa00";
      case "low":
        return "#00cc66";
      default:
        return "#999";
    }
  };

  const handleNodeHover = (node: any) => {
    setHighlightedNode(node || null);
  };

  const handleNodeClick = (node: any) => {
    alertingMap(node.id);
  };

  return (
    <Card className="w-full h-full border bg-background shadow-sm">
      <CardHeader className="flex items-center justify-between gap-4">
        <h2 className="text-lg font-semibold text-foreground">Карта атакуемых зон</h2>
        {highlightedNode && (
          <div className="text-sm text-muted-foreground max-w-xs truncate">
            {highlightedNode.name} · Уровень риска: {highlightedNode.risk.toUpperCase()}
          </div>
        )}
      </CardHeader>

      <CardContent className="relative h-[600px] overflow-hidden border rounded-md bg-muted">
        <ForceGraph2D
          ref={fgRef}
          width={window.innerWidth - 80}
          height={600}
          graphData={{ nodes, links }}
          nodeAutoColorBy="group"
          nodeLabel={(node: any) => `${node.name}\nРиск: ${node.risk}`}
          nodeCanvasObject={(node: any, ctx, globalScale) => {
            const label = node.name;
            const fontSize = 12 / globalScale;
            ctx.font = `${fontSize}px Inter`;
            const textWidth = ctx.measureText(label).width;
            const backgroundColor = getNodeColor(node.risk);

            ctx.fillStyle = backgroundColor;
            ctx.beginPath();
            ctx.arc(node.x, node.y, 8, 0, 2 * Math.PI);
            ctx.fill();

            ctx.fillStyle = theme === "dark" ? "white" : "black";
            ctx.fillText(label, node.x - textWidth / 2, node.y - 10);
          }}
          linkDirectionalArrowLength={5}
          linkDirectionalArrowRelPos={1}
          linkCanvasObjectMode={() => "after"}
          linkCanvasObject={(link: any, ctx, globalScale) => {
            const label = link.type || "связь";
            const fontSize = 10 / globalScale;
            ctx.font = `${fontSize}px Inter`;
            ctx.fillStyle = "#999";
            ctx.fillText(label, (link.source.x + link.target.x) / 2, (link.source.y + link.target.y) / 2);
          }}
          onNodeHover={handleNodeHover}
          onNodeClick={handleNodeClick}
        />
      </CardContent>
    </Card>
  );
};
