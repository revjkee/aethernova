import { FC, useMemo, useState } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { usePermission } from "@/shared/hooks/usePermission";
import { Role } from "@/shared/constants/roles";
import { useOnboardingStatus } from "@/features/hr-core/hooks/useOnboardingStatus";
import { cn } from "@/lib/utils";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { CheckCircleIcon, AlertTriangleIcon, XCircleIcon, DownloadIcon, Loader2Icon } from "lucide-react";
import { XAIExplanation } from "@/features/xai/components/XAIExplanation";
import { useOnboardingXAI } from "@/features/xai/hooks/useOnboardingXAI";
import html2canvas from "html2canvas";
import { saveAs } from "file-saver";

interface Props {
  candidateId: string;
}

export const OnboardingReadiness: FC<Props> = ({ candidateId }) => {
  const { can } = usePermission();
  const { status, loading, refetch } = useOnboardingStatus(candidateId);
  const { explanation, loading: xaiLoading } = useOnboardingXAI(candidateId);
  const [exporting, setExporting] = useState(false);
  const containerRef = useState<HTMLDivElement | null>(null)[0];

  const handleExport = async () => {
    if (!containerRef) return;
    setExporting(true);
    try {
      const canvas = await html2canvas(containerRef);
      canvas.toBlob(blob => {
        if (blob) saveAs(blob, `onboarding_${candidateId}.png`);
      });
    } finally {
      setExporting(false);
    }
  };

  const getColor = (percent: number) => {
    if (percent >= 90) return "text-green-600";
    if (percent >= 60) return "text-yellow-500";
    return "text-red-500";
  };

  const getIcon = (percent: number) => {
    if (percent >= 90) return <CheckCircleIcon className="w-4 h-4 text-green-600" />;
    if (percent >= 60) return <AlertTriangleIcon className="w-4 h-4 text-yellow-500" />;
    return <XCircleIcon className="w-4 h-4 text-red-500" />;
  };

  const steps = useMemo(() => {
    if (!status) return [];
    return [
      { key: "contractSigned", label: "Контракт", done: status.contractSigned },
      { key: "documentsUploaded", label: "Документы", done: status.documentsUploaded },
      { key: "accessGranted", label: "Доступы", done: status.accessGranted },
      { key: "trainingPassed", label: "Обучение", done: status.trainingPassed },
      { key: "biometricsDone", label: "Верификация", done: status.biometricsDone },
      { key: "hardwareReady", label: "Оборудование", done: status.hardwareReady }
    ];
  }, [status]);

  const readiness = useMemo(() => {
    if (!steps.length) return 0;
    const done = steps.filter(step => step.done).length;
    return Math.round((done / steps.length) * 100);
  }, [steps]);

  if (loading || !status) {
    return (
      <Card>
        <CardHeader>
          <Skeleton className="h-6 w-64 mb-2" />
          <Skeleton className="h-4 w-32" />
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
          <CardTitle className="text-xl">Готовность к онбордингу</CardTitle>
          <p className="text-sm text-muted-foreground">AI-модель оценки готовности кандидата к старту</p>
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
        <div className="flex items-center gap-3">
          {getIcon(readiness)}
          <span className={cn("text-xl font-bold", getColor(readiness))}>
            {readiness}%
          </span>
          <Badge variant="outline">{readiness >= 90 ? "Готов" : readiness >= 60 ? "Почти готов" : "Не готов"}</Badge>
        </div>

        <Progress value={readiness} className="h-3 rounded-full" />

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2">
          {steps.map(step => (
            <div key={step.key} className="flex items-center justify-between border-b pb-1">
              <span className="text-sm">{step.label}</span>
              <Badge variant={step.done ? "default" : "outline"}>
                {step.done ? "✓ Выполнено" : "✕ Ожидается"}
              </Badge>
            </div>
          ))}
        </div>

        {can(Role.SUPERVISOR) && explanation && !xaiLoading && (
          <div className="mt-6">
            <XAIExplanation
              explanation={explanation}
              title="AI-пояснение статуса онбординга"
            />
          </div>
        )}
      </CardContent>
    </Card>
  );
};
