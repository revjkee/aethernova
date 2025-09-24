import { FC, useMemo, useRef, useState } from "react";
import {
  RadarChart,
  Radar,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Tooltip,
  ResponsiveContainer,
  LabelList,
  Cell
} from "recharts";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { usePermission } from "@/shared/hooks/usePermission";
import { Role } from "@/shared/constants/roles";
import { useSkillRadar } from "@/features/hr-core/hooks/useSkillRadar";
import { useAICompetencyExplanation } from "@/features/xai/hooks/useAICompetencyExplanation";
import { XAIExplanation } from "@/features/xai/components/XAIExplanation";
import html2canvas from "html2canvas";
import { Button } from "@/components/ui/button";
import { DownloadIcon } from "lucide-react";
import { saveAs } from "file-saver";

interface Props {
  userId: string;
  compact?: boolean;
}

export const SkillRadarGraph: FC<Props> = ({ userId, compact = false }) => {
  const { can } = usePermission();
  const { data, loading } = useSkillRadar(userId);
  const { explanation, loading: xaiLoading } = useAICompetencyExplanation(userId);
  const chartRef = useRef<HTMLDivElement>(null);
  const [exporting, setExporting] = useState(false);

  const normalizedData = useMemo(() => {
    if (!data) return [];
    return data.map((item) => ({
      ...item,
      level: Math.min(Math.max(item.level, 0), 10),
      color: getSkillColor(item.level)
    }));
  }, [data]);

  const getSkillColor = (level: number): string => {
    if (level >= 8) return "#4ade80";      // green
    if (level >= 5) return "#facc15";      // yellow
    if (level >= 3) return "#f97316";      // orange
    return "#ef4444";                      // red
  };

  const handleExport = async () => {
    if (!chartRef.current) return;
    setExporting(true);
    try {
      const canvas = await html2canvas(chartRef.current);
      canvas.toBlob(blob => {
        if (blob) saveAs(blob, `skill_radar_${userId}.png`);
      });
    } finally {
      setExporting(false);
    }
  };

  if (loading || !data) {
    return (
      <Card className={cn("w-full", compact && "max-w-2xl")}>
        <CardHeader>
          <Skeleton className="h-6 w-64 mb-2" />
          <Skeleton className="h-4 w-32" />
        </CardHeader>
        <CardContent>
          <Skeleton className="h-[300px] w-full" />
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className={cn("transition-shadow hover:shadow-md", compact && "max-w-2xl")}>
      <CardHeader className="flex flex-col md:flex-row justify-between md:items-center">
        <div>
          <CardTitle className="text-xl">Навыки: Radar-граф</CardTitle>
          <p className="text-sm text-muted-foreground">AI-визуализация компетенций сотрудника</p>
        </div>

        <Button
          size="sm"
          variant="outline"
          onClick={handleExport}
          disabled={exporting}
        >
          <DownloadIcon className="w-4 h-4 mr-2" />
          {exporting ? "Экспорт..." : "Сохранить PNG"}
        </Button>
      </CardHeader>

      <CardContent className="space-y-4">
        <div ref={chartRef} className="w-full h-[360px]">
          <ResponsiveContainer width="100%" height="100%">
            <RadarChart outerRadius={120} data={normalizedData}>
              <PolarGrid />
              <PolarAngleAxis dataKey="skill" />
              <PolarRadiusAxis domain={[0, 10]} angle={30} />
              <Tooltip />
              <Radar
                name="Навыки"
                dataKey="level"
                stroke="#8884d8"
                fill="#8884d8"
                fillOpacity={0.4}
              >
                <LabelList dataKey="level" position="top" />
                {normalizedData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Radar>
            </RadarChart>
          </ResponsiveContainer>
        </div>

        {can(Role.SUPERVISOR) && explanation && !xaiLoading && (
          <div className="mt-4">
            <XAIExplanation explanation={explanation} title="AI-пояснение по компетенциям" />
          </div>
        )}
      </CardContent>
    </Card>
  );
};
