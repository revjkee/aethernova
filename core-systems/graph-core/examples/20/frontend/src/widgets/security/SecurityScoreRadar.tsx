// src/widgets/Security/SecurityScoreRadar.tsx
import React, { useEffect, useMemo, useState } from "react";
import { Radar, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Tooltip, ResponsiveContainer } from "recharts";
import { Card, CardHeader, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import { useSecurityMetrics } from "@/hooks/security/useSecurityMetrics";
import { useUserProfile } from "@/hooks/auth/useUserProfile";
import { Skeleton } from "@/components/ui/skeleton";
import { ThreatLevelTag } from "@/components/security/ThreatLevelTag";
import { ThreatScoreLegend } from "@/components/security/ThreatScoreLegend";
import { AuditIcon } from "lucide-react";

export const SecurityScoreRadar: React.FC = () => {
  const { metrics, loading } = useSecurityMetrics();
  const { user } = useUserProfile();
  const [baseline, setBaseline] = useState<number[]>([]);

  const radarData = useMemo(() => {
    if (!metrics || metrics.length === 0) return [];

    return metrics.map((m, i) => ({
      dimension: m.label,
      current: m.score,
      baseline: baseline[i] || 0,
    }));
  }, [metrics, baseline]);

  useEffect(() => {
    // simulate loading baseline from policy memory
    if (metrics.length > 0) {
      setBaseline(metrics.map(m => Math.min(100, m.score - Math.floor(Math.random() * 20 + 5))));
    }
  }, [metrics]);

  return (
    <Card className="w-full bg-background border border-border shadow-lg">
      <CardHeader className="flex justify-between items-start md:items-center gap-4 flex-col md:flex-row">
        <div>
          <h2 className="text-lg font-semibold text-foreground">Оценка безопасности</h2>
          <p className="text-sm text-muted-foreground">
            Визуализация критических показателей по модели Zero Trust Security Layer
          </p>
        </div>
        <ThreatLevelTag score={calculateGlobalScore(metrics)} />
      </CardHeader>

      <CardContent>
        {loading ? (
          <div className="h-[300px] w-full flex justify-center items-center">
            <Skeleton className="w-1/2 h-[250px] rounded-xl bg-muted" />
          </div>
        ) : (
          <ResponsiveContainer width="100%" height={350}>
            <RadarChart cx="50%" cy="50%" outerRadius="90%" data={radarData}>
              <PolarGrid />
              <PolarAngleAxis dataKey="dimension" stroke="#ccc" fontSize={11} />
              <PolarRadiusAxis angle={30} domain={[0, 100]} tickCount={6} />
              <Radar name="Текущий уровень" dataKey="current" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.6} />
              <Radar name="Базовый уровень" dataKey="baseline" stroke="#94a3b8" fill="#94a3b8" fillOpacity={0.3} />
              <Tooltip
                contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155" }}
                itemStyle={{ color: "#f1f5f9", fontSize: 12 }}
              />
            </RadarChart>
          </ResponsiveContainer>
        )}

        <div className="mt-6 flex justify-between items-center flex-wrap gap-4">
          <ThreatScoreLegend metrics={metrics} />
          <div className="flex items-center text-sm text-muted-foreground gap-2">
            <AuditIcon size={14} /> Последнее обновление:{" "}
            <span className="text-foreground font-medium">
              {new Date().toLocaleDateString()} {new Date().toLocaleTimeString()}
            </span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

function calculateGlobalScore(metrics: Array<{ score: number }>): number {
  if (!metrics || metrics.length === 0) return 0;
  const sum = metrics.reduce((acc, m) => acc + m.score, 0);
  return Math.round(sum / metrics.length);
}
