import { FC, useCallback, useMemo, useState } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { usePermission } from "@/shared/hooks/usePermission";
import { Role } from "@/shared/constants/roles";
import { useBackgroundCheck } from "@/features/hr-core/hooks/useBackgroundCheck";
import { Progress } from "@/components/ui/progress";
import { CheckCircleIcon, XCircleIcon, AlertCircleIcon, Loader2Icon, DownloadIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { toast } from "@/components/ui/use-toast";
import { cn } from "@/lib/utils";
import html2canvas from "html2canvas";
import { saveAs } from "file-saver";
import { XAIExplanation } from "@/features/xai/components/XAIExplanation";
import { useBackgroundXAI } from "@/features/xai/hooks/useBackgroundXAI";

interface Props {
  candidateId: string;
  compact?: boolean;
}

export const BackgroundCheckStatus: FC<Props> = ({ candidateId, compact = false }) => {
  const { can } = usePermission();
  const { status, loading, refetch } = useBackgroundCheck(candidateId);
  const { explanation, loading: xaiLoading } = useBackgroundXAI(candidateId);
  const [exporting, setExporting] = useState(false);
  const containerRef = useState<HTMLDivElement | null>(null)[0];

  const handleExport = async () => {
    if (!containerRef) return;
    setExporting(true);
    try {
      const canvas = await html2canvas(containerRef);
      canvas.toBlob(blob => {
        if (blob) saveAs(blob, `background_check_${candidateId}.png`);
      });
    } finally {
      setExporting(false);
    }
  };

  const getIcon = (state: string) => {
    switch (state) {
      case "passed":
        return <CheckCircleIcon className="w-4 h-4 text-green-600" />;
      case "failed":
        return <XCircleIcon className="w-4 h-4 text-red-500" />;
      case "pending":
        return <Loader2Icon className="w-4 h-4 animate-spin text-muted-foreground" />;
      default:
        return <AlertCircleIcon className="w-4 h-4 text-yellow-500" />;
    }
  };

  const items = useMemo(() => {
    if (!status) return [];
    return [
      { label: "Паспортные данные", key: "identity", state: status.identity },
      { label: "Криминальное прошлое", key: "criminal", state: status.criminal },
      { label: "Образование", key: "education", state: status.education },
      { label: "Профессиональный опыт", key: "experience", state: status.experience },
      { label: "Социальные проверки", key: "social", state: status.social }
    ];
  }, [status]);

  const passedCount = items.filter(i => i.state === "passed").length;
  const totalCount = items.length;
  const progress = Math.round((passedCount / totalCount) * 100);

  if (loading || !status) {
    return (
      <Card className={cn("w-full", compact && "max-w-2xl")}>
        <CardHeader>
          <Skeleton className="h-6 w-64 mb-2" />
          <Skeleton className="h-4 w-32" />
        </CardHeader>
        <CardContent>
          <Skeleton className="h-[280px] w-full" />
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className={cn("transition-shadow hover:shadow-md", compact && "max-w-2xl")}>
      <CardHeader className="flex flex-col md:flex-row justify-between md:items-center">
        <div>
          <CardTitle className="text-xl">Проверка Background кандидата</CardTitle>
          <p className="text-sm text-muted-foreground">AI-модуль оценки благонадёжности</p>
        </div>
        <div className="flex gap-2 mt-4 md:mt-0">
          <Button variant="outline" size="sm" onClick={refetch}>
            <Loader2Icon className="w-4 h-4 mr-2 animate-spin" />
            Обновить
          </Button>
          <Button variant="outline" size="sm" onClick={handleExport} disabled={exporting}>
            <DownloadIcon className="w-4 h-4 mr-2" />
            {exporting ? "Экспорт..." : "Сохранить PNG"}
          </Button>
        </div>
      </CardHeader>

      <CardContent ref={containerRef} className="space-y-6">
        <div className="space-y-3">
          {items.map(item => (
            <div key={item.key} className="flex justify-between items-center border-b pb-2">
              <span className="text-sm">{item.label}</span>
              <div className="flex items-center gap-2">
                {getIcon(item.state)}
                <Badge variant="outline">
                  {item.state === "passed"
                    ? "Пройдено"
                    : item.state === "failed"
                    ? "Провалено"
                    : item.state === "pending"
                    ? "Ожидается"
                    : "Неизвестно"}
                </Badge>
              </div>
            </div>
          ))}
        </div>

        <div>
          <p className="text-sm text-muted-foreground mb-1 font-semibold">Общий прогресс:</p>
          <Progress value={progress} className="h-3 rounded-full" />
        </div>

        {can(Role.SUPERVISOR) && explanation && !xaiLoading && (
          <div className="mt-6">
            <XAIExplanation explanation={explanation} title="AI-пояснение к результатам проверки" />
          </div>
        )}
      </CardContent>
    </Card>
  );
};
