import { FC, useMemo, useState } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { usePermission } from "@/shared/hooks/usePermission";
import { Role } from "@/shared/constants/roles";
import { useCandidateRanking } from "@/features/hr-core/hooks/useCandidateRanking";
import { Progress } from "@/components/ui/progress";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { DownloadIcon, Loader2Icon, TrendingUpIcon, TrendingDownIcon, MinusIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { XAIExplanation } from "@/features/xai/components/XAIExplanation";
import { useRankXAI } from "@/features/xai/hooks/useRankXAI";
import html2canvas from "html2canvas";
import { saveAs } from "file-saver";

interface Props {
  candidateId: string;
  vacancyId: string;
}

export const CandidateRankIndicator: FC<Props> = ({ candidateId, vacancyId }) => {
  const { can } = usePermission();
  const { ranking, loading, refetch } = useCandidateRanking(candidateId, vacancyId);
  const { explanation, loading: xaiLoading } = useRankXAI(candidateId, vacancyId);
  const [exporting, setExporting] = useState(false);
  const containerRef = useState<HTMLDivElement | null>(null)[0];

  const handleExport = async () => {
    if (!containerRef) return;
    setExporting(true);
    try {
      const canvas = await html2canvas(containerRef);
      canvas.toBlob(blob => {
        if (blob) saveAs(blob, `rank_report_${candidateId}_${vacancyId}.png`);
      });
    } finally {
      setExporting(false);
    }
  };

  const getTrendIcon = (trend: number) => {
    if (trend > 0) return <TrendingUpIcon className="w-4 h-4 text-green-600" />;
    if (trend < 0) return <TrendingDownIcon className="w-4 h-4 text-red-500" />;
    return <MinusIcon className="w-4 h-4 text-muted-foreground" />;
  };

  const rankScoreColor = (score: number) => {
    if (score >= 85) return "text-green-600";
    if (score >= 65) return "text-yellow-500";
    return "text-red-500";
  };

  const isTopRank = useMemo(() => ranking?.rank === 1, [ranking]);

  if (loading || !ranking) {
    return (
      <Card>
        <CardHeader>
          <Skeleton className="h-6 w-64 mb-2" />
          <Skeleton className="h-4 w-32" />
        </CardHeader>
        <CardContent>
          <Skeleton className="h-[100px] w-full" />
        </CardContent>
      </Card>
    );
  }

  return (
    <Card ref={containerRef} className="transition-shadow hover:shadow-md">
      <CardHeader className="flex flex-col md:flex-row justify-between md:items-center">
        <div>
          <CardTitle className="text-xl">Рейтинг кандидата</CardTitle>
          <p className="text-sm text-muted-foreground">
            Позиция в списке претендентов по AI-модели
          </p>
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

      <CardContent className="space-y-6">
        <div className="text-sm text-muted-foreground">
          <p>Кандидат: <strong>{ranking.candidateName}</strong></p>
          <p>Вакансия: <strong>{ranking.vacancyTitle}</strong></p>
        </div>

        <div className="flex items-center gap-3">
          <Badge variant="outline" className="text-xs">
            Место в рейтинге: <strong className="ml-1">{ranking.rank} / {ranking.total}</strong>
          </Badge>
          {getTrendIcon(ranking.trend)}
          <span className={cn("text-lg font-bold", rankScoreColor(ranking.score))}>
            {ranking.score}%
          </span>
        </div>

        <Progress value={ranking.score} className="h-3 rounded-full" />

        {ranking.keyFactors?.length > 0 && (
          <div className="space-y-4 mt-4">
            <p className="text-sm font-semibold text-muted-foreground">Ключевые факторы:</p>
            <ul className="list-disc list-inside text-sm text-muted-foreground space-y-1">
              {ranking.keyFactors.map((f, i) => (
                <li key={i}>{f}</li>
              ))}
            </ul>
          </div>
        )}

        {can(Role.SUPERVISOR) && explanation && !xaiLoading && (
          <div className="mt-6">
            <XAIExplanation
              explanation={explanation}
              title="Пояснение AI-ранжирования"
            />
          </div>
        )}
      </CardContent>
    </Card>
  );
};
