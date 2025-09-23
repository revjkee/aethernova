import { FC, useMemo } from "react";
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, LabelList } from "recharts";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import { usePermission } from "@/shared/hooks/usePermission";
import { useCompetencyMatrix } from "@/widgets/HR/hooks/useCompetencyMatrix";
import { Role } from "@/shared/constants/roles";
import { Skeleton } from "@/components/ui/skeleton";
import { XAIExplanation } from "@/features/xai/components/XAIExplanation";
import { AICompetencyColorMap, normalizeScore } from "@/features/hr-core/utils/competencyColors";
import { Button } from "@/components/ui/button";
import { DownloadIcon } from "lucide-react";
import html2canvas from "html2canvas";
import { saveAs } from "file-saver";

interface Props {
  userId: string;
  compact?: boolean;
}

export const CompetencyMatrixChart: FC<Props> = ({ userId, compact = false }) => {
  const { matrix, loading, explanation } = useCompetencyMatrix(userId);
  const { can } = usePermission();

  const processedData = useMemo(() => {
    if (!matrix) return [];
    return matrix.map(row => ({
      skill: row.name,
      score: normalizeScore(row.score),
      weight: row.weight,
      color: AICompetencyColorMap[row.category] || "#8884d8"
    }));
  }, [matrix]);

  const handleExport = async () => {
    const chartElement = document.getElementById("competency-chart");
    if (!chartElement) return;
    const canvas = await html2canvas(chartElement);
    canvas.toBlob(blob => {
      if (blob) {
        saveAs(blob, `competency_matrix_${userId}.png`);
      }
    });
  };

  if (loading || !matrix) {
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
    <Card className={cn("transition-shadow hover:shadow-lg", compact && "max-w-2xl")}>
      <CardHeader className="flex flex-col md:flex-row justify-between items-start md:items-center">
        <div>
          <CardTitle className="text-xl">Матрица компетенций</CardTitle>
          <p className="text-sm text-muted-foreground">AI-анализ и визуализация уровня навыков</p>
        </div>
        <div className="mt-4 md:mt-0">
          <Button onClick={handleExport} size="sm" variant="outline">
            <DownloadIcon className="w-4 h-4 mr-2" />
            Экспорт
          </Button>
        </div>
      </CardHeader>

      <CardContent className="relative">
        <div id="competency-chart" className="w-full h-[360px]">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={processedData} layout="vertical" margin={{ top: 20, right: 40, left: 20, bottom: 20 }}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis type="number" domain={[0, 10]} />
              <YAxis dataKey="skill" type="category" width={150} />
              <Tooltip />
              <Legend />
              <Bar dataKey="score" name="Уровень" isAnimationActive radius={[0, 4, 4, 0]}>
                <LabelList dataKey="score" position="right" fill="#333" fontSize={12} />
                {processedData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {can(Role.SUPERVISOR) && explanation && (
          <div className="mt-6">
            <XAIExplanation explanation={explanation} title="Объяснение оценки AI" />
          </div>
        )}
      </CardContent>
    </Card>
  );
};
