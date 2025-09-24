import { FC, useMemo, useState, useRef } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { usePermission } from "@/shared/hooks/usePermission";
import { Role } from "@/shared/constants/roles";
import { usePersonalityProfile } from "@/features/hr-core/hooks/usePersonalityProfile";
import { Progress } from "@/components/ui/progress";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { DownloadIcon } from "lucide-react";
import html2canvas from "html2canvas";
import { saveAs } from "file-saver";
import { XAIExplanation } from "@/features/xai/components/XAIExplanation";
import { usePersonalityXAI } from "@/features/xai/hooks/usePersonalityXAI";

interface Props {
  candidateId: string;
  compact?: boolean;
}

export const PersonalityDiagnosticsPanel: FC<Props> = ({ candidateId, compact = false }) => {
  const { can } = usePermission();
  const { profile, loading } = usePersonalityProfile(candidateId);
  const { explanation, loading: xaiLoading } = usePersonalityXAI(candidateId);
  const containerRef = useRef<HTMLDivElement>(null);
  const [exporting, setExporting] = useState(false);

  const traits = useMemo(() => {
    if (!profile) return [];
    return [
      { label: "Открытость опыту", key: "openness", value: profile.openness },
      { label: "Добросовестность", key: "conscientiousness", value: profile.conscientiousness },
      { label: "Экстраверсия", key: "extraversion", value: profile.extraversion },
      { label: "Уживчивость", key: "agreeableness", value: profile.agreeableness },
      { label: "Невротизм", key: "neuroticism", value: profile.neuroticism }
    ];
  }, [profile]);

  const getBarColor = (value: number): string => {
    if (value >= 80) return "bg-green-500";
    if (value >= 60) return "bg-yellow-400";
    if (value >= 40) return "bg-orange-400";
    return "bg-red-500";
  };

  const handleExport = async () => {
    if (!containerRef.current) return;
    setExporting(true);
    try {
      const canvas = await html2canvas(containerRef.current);
      canvas.toBlob(blob => {
        if (blob) saveAs(blob, `personality_profile_${candidateId}.png`);
      });
    } finally {
      setExporting(false);
    }
  };

  if (loading || !profile) {
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
          <CardTitle className="text-xl">Психологический профиль</CardTitle>
          <p className="text-sm text-muted-foreground">Анализ по Big Five и интерпретация AI</p>
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

      <CardContent ref={containerRef} className="space-y-6">
        {traits.map((trait) => (
          <div key={trait.key}>
            <div className="flex justify-between mb-1">
              <span className="text-sm font-medium">{trait.label}</span>
              <span className="text-sm text-muted-foreground">{trait.value}%</span>
            </div>
            <Progress
              value={trait.value}
              className={cn("h-3 rounded-full", getBarColor(trait.value))}
            />
          </div>
        ))}

        {can(Role.SUPERVISOR) && explanation && !xaiLoading && (
          <div className="mt-4">
            <XAIExplanation explanation={explanation} title="AI-пояснение психопрофиля" />
          </div>
        )}
      </CardContent>
    </Card>
  );
};
