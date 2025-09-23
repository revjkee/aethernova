import { FC, useMemo, useState } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { usePermission } from "@/shared/hooks/usePermission";
import { Role } from "@/shared/constants/roles";
import { useRolePrediction } from "@/features/hr-core/hooks/useRolePrediction";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { AlertTriangleIcon, CheckCircleIcon, XCircleIcon, Loader2Icon, DownloadIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { XAIExplanation } from "@/features/xai/components/XAIExplanation";
import { useRoleFitXAI } from "@/features/xai/hooks/useRoleFitXAI";
import html2canvas from "html2canvas";
import { saveAs } from "file-saver";

interface Props {
  candidateId: string;
  roleId: string;
  compact?: boolean;
}

export const RoleFitPredictor: FC<Props> = ({ candidateId, roleId, compact = false }) => {
  const { can } = usePermission();
  const { prediction, loading, refetch } = useRolePrediction(candidateId, roleId);
  const { explanation, loading: xaiLoading } = useRoleFitXAI(candidateId, roleId);
  const [exporting, setExporting] = useState(false);
  const containerRef = useState<HTMLDivElement | null>(null)[0];

  const handleExport = async () => {
    if (!containerRef) return;
    setExporting(true);
    try {
      const canvas = await html2canvas(containerRef);
      canvas.toBlob(blob => {
        if (blob) saveAs(blob, `role_fit_${candidateId}_${roleId}.png`);
      });
    } finally {
      setExporting(false);
    }
  };

  const getColor = (score: number) => {
    if (score >= 85) return "text-green-600";
    if (score >= 60) return "text-yellow-500";
    return "text-red-500";
  };

  const getIcon = (score: number) => {
    if (score >= 85) return <CheckCircleIcon className="w-4 h-4 text-green-600" />;
    if (score >= 60) return <AlertTriangleIcon className="w-4 h-4 text-yellow-500" />;
    return <XCircleIcon className="w-4 h-4 text-red-500" />;
  };

  const criteria = useMemo(() => {
    if (!prediction) return [];
    return prediction.criteria.map(c => ({
      ...c,
      label: c.label,
      score: c.matchPercent,
      comment: c.comment
    }));
  }, [prediction]);

  if (loading || !prediction) {
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
          <CardTitle className="text-xl">Прогноз соответствия роли</CardTitle>
          <p className="text-sm text-muted-foreground">AI-модель оценки кандидата на роль</p>
        </div>
        <div className="flex gap-2 mt-4 md:mt-0">
          <Button variant="outline" size="sm" onClick={refetch}>
            <Loader2Icon className="w-4 h-4 mr-2 animate-spin" />
            Обновить
          </Button>
          {can(Role.SUPERVISOR) && (
            <Button variant="outline" size="sm" onClick={handleExport} disabled={exporting}>
              <DownloadIcon className="w-4 h-4 mr-2" />
              {exporting ? "Экспорт…" : "Сохранить PNG"}
            </Button>
          )}
        </div>
      </CardHeader>

      <CardContent ref={containerRef} className="space-y-6">
        <div className="text-sm text-muted-foreground">
          <p>Кандидат: <strong>{prediction.candidateName}</strong></p>
          <p>Роль: <strong>{prediction.roleTitle}</strong></p>
        </div>

        <div className="mt-2">
          <p className="text-sm font-semibold text-muted-foreground">Общая вероятность соответствия:</p>
          <div className="flex items-center gap-2 mt-1">
            {getIcon(prediction.overallFit)}
            <span className={cn("text-xl font-bold", getColor(prediction.overallFit))}>
              {prediction.overallFit}%
            </span>
          </div>
          <Progress value={prediction.overallFit} className="h-3 rounded-full mt-2" />
        </div>

        <div className="space-y-4 pt-2">
          {criteria.map(criterion => (
            <div key={criterion.label} className="space-y-1 border-b pb-2">
              <div className="flex justify-between items-center">
                <div>
                  <span className="text-sm font-medium">{criterion.label}</span>
                  <p className="text-xs text-muted-foreground">{criterion.comment}</p>
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant="outline" className={getColor(criterion.score)}>
                    {criterion.score}%
                  </Badge>
                </div>
              </div>
              <Progress value={criterion.score} className="h-2 rounded-full" />
            </div>
          ))}
        </div>

        {can(Role.SUPERVISOR) && explanation && !xaiLoading && (
          <div className="mt-6">
            <XAIExplanation
              explanation={explanation}
              title="AI-пояснение прогноза"
            />
          </div>
        )}
      </CardContent>
    </Card>
  );
};
