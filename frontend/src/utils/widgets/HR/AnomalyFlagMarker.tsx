import { FC, useMemo, useState } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { useAnomalyFlags } from "@/features/hr-core/hooks/useAnomalyFlags";
import { usePermission } from "@/shared/hooks/usePermission";
import { Role } from "@/shared/constants/roles";
import { DownloadIcon, AlertTriangleIcon, ShieldOffIcon, Loader2Icon } from "lucide-react";
import { XAIExplanation } from "@/features/xai/components/XAIExplanation";
import { useAnomalyXAI } from "@/features/xai/hooks/useAnomalyXAI";
import html2canvas from "html2canvas";
import { saveAs } from "file-saver";
import { cn } from "@/lib/utils";

interface Props {
  candidateId: string;
  context?: "profile" | "review";
}

const categoryColors: Record<string, string> = {
  behavior: "bg-yellow-500",
  data: "bg-blue-500",
  speech: "bg-purple-500",
  documents: "bg-red-500",
  default: "bg-muted"
};

export const AnomalyFlagMarker: FC<Props> = ({ candidateId, context = "profile" }) => {
  const { can } = usePermission();
  const { flags, loading, refetch } = useAnomalyFlags(candidateId);
  const { explanation, loading: xaiLoading } = useAnomalyXAI(candidateId);
  const [exporting, setExporting] = useState(false);
  const containerRef = useState<HTMLDivElement | null>(null)[0];

  const handleExport = async () => {
    if (!containerRef) return;
    setExporting(true);
    try {
      const canvas = await html2canvas(containerRef);
      canvas.toBlob(blob => {
        if (blob) saveAs(blob, `anomaly_flags_${candidateId}.png`);
      });
    } finally {
      setExporting(false);
    }
  };

  const criticalCount = useMemo(() => {
    return flags?.filter(f => f.severity === "critical").length ?? 0;
  }, [flags]);

  const renderFlag = (flag: any, index: number) => {
    const color = categoryColors[flag.category] || categoryColors.default;
    return (
      <div
        key={index}
        className={cn(
          "p-3 rounded-md border flex flex-col gap-1 bg-background",
          flag.severity === "critical" ? "border-red-600" : "border-muted"
        )}
      >
        <div className="flex items-center gap-2">
          <Badge className={cn("text-white text-xs", color)}>{flag.category.toUpperCase()}</Badge>
          {flag.severity === "critical" ? (
            <AlertTriangleIcon className="w-4 h-4 text-red-600" />
          ) : (
            <ShieldOffIcon className="w-4 h-4 text-muted-foreground" />
          )}
          <span className="text-sm font-medium text-muted-foreground">{flag.title}</span>
        </div>
        {flag.description && (
          <p className="text-xs text-muted-foreground">{flag.description}</p>
        )}
        {flag.timestamp && (
          <p className="text-[10px] text-muted-foreground mt-1">Дата: {new Date(flag.timestamp).toLocaleString()}</p>
        )}
      </div>
    );
  };

  if (loading || !flags) {
    return (
      <Card>
        <CardHeader>
          <Skeleton className="h-6 w-48 mb-2" />
        </CardHeader>
        <CardContent>
          <Skeleton className="h-[120px] w-full" />
        </CardContent>
      </Card>
    );
  }

  return (
    <Card ref={containerRef} className="transition-shadow hover:shadow-md">
      <CardHeader className="flex flex-col md:flex-row justify-between md:items-center">
        <div>
          <CardTitle className="text-xl">Флаги аномалий</CardTitle>
          <p className="text-sm text-muted-foreground">Анализ поведения и данных кандидата</p>
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
        {flags.length === 0 ? (
          <p className="text-sm text-muted-foreground">Аномалий не обнаружено.</p>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {flags.map((flag, index) => renderFlag(flag, index))}
          </div>
        )}

        {can(Role.SUPERVISOR) && explanation && !xaiLoading && (
          <div className="mt-6">
            <XAIExplanation
              explanation={explanation}
              title="AI-пояснение выявленных аномалий"
            />
          </div>
        )}
      </CardContent>
    </Card>
  );
};
