import { FC, useMemo, useState } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { usePermission } from "@/shared/hooks/usePermission";
import { Role } from "@/shared/constants/roles";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Button } from "@/components/ui/button";
import { DownloadIcon, Loader2Icon } from "lucide-react";
import { cn } from "@/lib/utils";
import { useCultureMatch } from "@/features/hr-core/hooks/useCultureMatch";
import { useXAIExplanation } from "@/features/xai/hooks/useXAIExplanation";
import { XAIExplanation } from "@/features/xai/components/XAIExplanation";
import html2canvas from "html2canvas";
import { saveAs } from "file-saver";

interface Props {
  candidateId: string;
  compact?: boolean;
}

const traitColors: Record<string, string> = {
  integrity: "bg-green-600",
  innovation: "bg-blue-500",
  collaboration: "bg-violet-500",
  accountability: "bg-orange-500",
  resilience: "bg-pink-500",
  empathy: "bg-yellow-400",
  adaptability: "bg-teal-500",
  default: "bg-muted"
};

export const CultureMatchWidget: FC<Props> = ({ candidateId, compact = false }) => {
  const { can } = usePermission();
  const { data, loading, refetch } = useCultureMatch(candidateId);
  const { explanation, loading: xaiLoading } = useXAIExplanation(candidateId, "culture_match");
  const [exporting, setExporting] = useState(false);
  const containerRef = useState<HTMLDivElement | null>(null)[0];

  const handleExport = async () => {
    if (!containerRef) return;
    setExporting(true);
    try {
      const canvas = await html2canvas(containerRef);
      canvas.toBlob(blob => {
        if (blob) saveAs(blob, `culture_match_${candidateId}.png`);
      });
    } finally {
      setExporting(false);
    }
  };

  const sortedTraits = useMemo(() => {
    if (!data?.traits) return [];
    return [...data.traits].sort((a, b) => b.score - a.score);
  }, [data]);

  if (loading || !data) {
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
          <CardTitle className="text-xl">Совпадение с культурой компании</CardTitle>
          <p className="text-sm text-muted-foreground">Анализ ценностной совместимости</p>
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
        <div className="space-y-4">
          {sortedTraits.map((trait, idx) => (
            <div key={idx}>
              <div className="flex justify-between items-center mb-1">
                <div className="flex items-center gap-2">
                  <Badge className={cn("text-white text-xs", traitColors[trait.key] || traitColors.default)}>
                    {trait.label}
                  </Badge>
                </div>
                <span className="text-sm text-muted-foreground">{(trait.score * 100).toFixed(1)}%</span>
              </div>
              <Progress value={trait.score * 100} />
            </div>
          ))}
        </div>

        {can(Role.SUPERVISOR) && explanation && !xaiLoading && (
          <div className="mt-6">
            <XAIExplanation
              explanation={explanation}
              title="AI-пояснение совпадений"
            />
          </div>
        )}
      </CardContent>
    </Card>
  );
};
