import { FC, useMemo, useState } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { usePermission } from "@/shared/hooks/usePermission";
import { Role } from "@/shared/constants/roles";
import { useEthicsAssessment } from "@/features/hr-core/hooks/useEthicsAssessment";
import { cn } from "@/lib/utils";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { CheckCircleIcon, AlertTriangleIcon, XCircleIcon, Loader2Icon, DownloadIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { XAIExplanation } from "@/features/xai/components/XAIExplanation";
import { useEthicsXAI } from "@/features/xai/hooks/useEthicsXAI";
import html2canvas from "html2canvas";
import { saveAs } from "file-saver";

interface Props {
  candidateId: string;
  compact?: boolean;
}

export const EthicsCompatibilityView: FC<Props> = ({ candidateId, compact = false }) => {
  const { can } = usePermission();
  const { assessment, loading, refetch } = useEthicsAssessment(candidateId);
  const { explanation, loading: xaiLoading } = useEthicsXAI(candidateId);
  const [exporting, setExporting] = useState(false);
  const containerRef = useState<HTMLDivElement | null>(null)[0];

  const handleExport = async () => {
    if (!containerRef) return;
    setExporting(true);
    try {
      const canvas = await html2canvas(containerRef);
      canvas.toBlob(blob => {
        if (blob) saveAs(blob, `ethics_report_${candidateId}.png`);
      });
    } finally {
      setExporting(false);
    }
  };

  const getColor = (score: number): string => {
    if (score >= 85) return "text-green-600";
    if (score >= 70) return "text-yellow-500";
    return "text-red-500";
  };

  const getIcon = (score: number) => {
    if (score >= 85) return <CheckCircleIcon className="w-4 h-4 text-green-600" />;
    if (score >= 70) return <AlertTriangleIcon className="w-4 h-4 text-yellow-500" />;
    return <XCircleIcon className="w-4 h-4 text-red-500" />;
  };

  const metrics = useMemo(() => {
    if (!assessment) return [];
    return [
      {
        key: "alignment",
        label: "AI Alignment",
        description: "Уровень соответствия этическим AI-стандартам",
        score: assessment.alignment
      },
      {
        key: "biasSensitivity",
        label: "Bias Sensitivity",
        description: "Чувствительность к предвзятости и дискриминации",
        score: assessment.biasSensitivity
      },
      {
        key: "zeroHarm",
        label: "Zero Harm",
        description: "Минимизация вреда и негативных последствий",
        score: assessment.zeroHarm
      },
      {
        key: "riskAwareness",
        label: "Ethical Risk",
        description: "Осведомлённость об этических рисках",
        score: assessment.riskAwareness
      },
      {
        key: "consentHandling",
        label: "Consent Handling",
        description: "Правильное обращение с согласием пользователя",
        score: assessment.consentHandling
      }
    ];
  }, [assessment]);

  const avgScore = useMemo(() => {
    if (!metrics.length) return 0;
    return Math.round(metrics.reduce((sum, m) => sum + m.score, 0) / metrics.length);
  }, [metrics]);

  if (loading || !assessment) {
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
          <CardTitle className="text-xl">AI-этическая совместимость</CardTitle>
          <p className="text-sm text-muted-foreground">Оценка по метрикам доверия и моральной осознанности</p>
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
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {metrics.map(metric => (
            <div key={metric.key} className="space-y-1 border-b pb-2">
              <div className="flex justify-between items-center">
                <div>
                  <span className="text-sm font-medium">{metric.label}</span>
                  <p className="text-xs text-muted-foreground">{metric.description}</p>
                </div>
                <div className="flex items-center gap-2">
                  {getIcon(metric.score)}
                  <Badge variant="outline" className={getColor(metric.score)}>
                    {metric.score}/100
                  </Badge>
                </div>
              </div>
              <Progress value={metric.score} className="h-2 rounded-full" />
            </div>
          ))}
        </div>

        <div className="pt-2">
          <p className="text-sm text-muted-foreground mb-1 font-semibold">Итоговая оценка:</p>
          <Progress value={avgScore} className="h-3 rounded-full" />
          <div className={cn("text-sm font-semibold mt-1", getColor(avgScore))}>
            {avgScore}/100 — {avgScore >= 85 ? "Высокая совместимость" : avgScore >= 70 ? "Средняя" : "Критическая"}
          </div>
        </div>

        {can(Role.SUPERVISOR) && explanation && !xaiLoading && (
          <div className="mt-6">
            <XAIExplanation
              explanation={explanation}
              title="AI-пояснение по этической совместимости"
            />
          </div>
        )}
      </CardContent>
    </Card>
  );
};
