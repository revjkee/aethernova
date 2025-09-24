import { FC, useState, useMemo } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { DownloadIcon, ShieldIcon, ShieldAlertIcon, Loader2Icon } from "lucide-react";
import { usePermission } from "@/shared/hooks/usePermission";
import { Role } from "@/shared/constants/roles";
import { useClearanceData } from "@/features/hr-core/hooks/useClearanceData";
import { useXAIExplanation } from "@/features/xai/hooks/useXAIExplanation";
import { XAIExplanation } from "@/features/xai/components/XAIExplanation";
import html2canvas from "html2canvas";
import { saveAs } from "file-saver";
import { cn } from "@/lib/utils";

interface Props {
  candidateId: string;
  compact?: boolean;
}

const levelColors: Record<string, string> = {
  "L1": "bg-green-600",
  "L2": "bg-blue-600",
  "L3": "bg-yellow-600",
  "L4": "bg-orange-600",
  "L5": "bg-red-600",
  "default": "bg-muted"
};

export const AccessClearanceLevelView: FC<Props> = ({ candidateId, compact = false }) => {
  const { can } = usePermission();
  const { clearance, loading, refetch } = useClearanceData(candidateId);
  const { explanation, loading: xaiLoading } = useXAIExplanation(candidateId, "clearance_level");
  const [exporting, setExporting] = useState(false);
  const containerRef = useState<HTMLDivElement | null>(null)[0];

  const handleExport = async () => {
    if (!containerRef) return;
    setExporting(true);
    try {
      const canvas = await html2canvas(containerRef);
      canvas.toBlob(blob => {
        if (blob) saveAs(blob, `access_clearance_${candidateId}.png`);
      });
    } finally {
      setExporting(false);
    }
  };

  const levelBadge = useMemo(() => {
    const level = clearance?.level || "default";
    return (
      <Badge className={cn("text-white", levelColors[level] || levelColors["default"])}>
        Уровень доступа: {level}
      </Badge>
    );
  }, [clearance]);

  if (loading || !clearance) {
    return (
      <Card>
        <CardHeader>
          <Skeleton className="h-6 w-48 mb-2" />
        </CardHeader>
        <CardContent>
          <Skeleton className="h-[100px] w-full" />
        </CardContent>
      </Card>
    );
  }

  return (
    <Card ref={containerRef} className={cn("transition-shadow hover:shadow-md", compact && "max-w-2xl")}>
      <CardHeader className="flex flex-col md:flex-row justify-between md:items-center">
        <div>
          <CardTitle className="text-xl">Уровень доступа</CardTitle>
          <p className="text-sm text-muted-foreground">Оценка кандидата по модели допуска</p>
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

      <CardContent className="space-y-4">
        <div className="flex items-center gap-4">
          {levelBadge}
          {clearance.critical ? (
            <ShieldAlertIcon className="w-5 h-5 text-red-600" />
          ) : (
            <ShieldIcon className="w-5 h-5 text-green-600" />
          )}
          <span className="text-sm text-muted-foreground">{clearance.critical ? "Найден критический риск" : "Риск не выявлен"}</span>
        </div>

        <div className="mt-2">
          <p className="text-sm text-muted-foreground">
            Политика: {clearance.policyName || "Не определена"} <br />
            Доступ к системам: {clearance.systems?.join(", ") || "Нет"} <br />
            Требования соответствия: {clearance.requirements?.length || 0}
          </p>
        </div>

        {clearance.notes && (
          <div className="mt-2">
            <p className="text-sm text-muted-foreground italic">Комментарий модели: {clearance.notes}</p>
          </div>
        )}

        {can(Role.SUPERVISOR) && explanation && !xaiLoading && (
          <div className="mt-6">
            <XAIExplanation
              explanation={explanation}
              title="AI-пояснение уровня допуска"
            />
          </div>
        )}
      </CardContent>
    </Card>
  );
};
