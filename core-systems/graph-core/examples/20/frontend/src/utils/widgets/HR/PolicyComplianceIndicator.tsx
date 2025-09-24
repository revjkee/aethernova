import { FC, useMemo, useState } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { usePermission } from "@/shared/hooks/usePermission";
import { Role } from "@/shared/constants/roles";
import { usePolicyCompliance } from "@/features/hr-core/hooks/usePolicyCompliance";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { CheckCircleIcon, XCircleIcon, AlertTriangleIcon, Loader2Icon, DownloadIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { toast } from "@/components/ui/use-toast";
import { cn } from "@/lib/utils";
import html2canvas from "html2canvas";
import { saveAs } from "file-saver";
import { XAIExplanation } from "@/features/xai/components/XAIExplanation";
import { useComplianceXAI } from "@/features/xai/hooks/useComplianceXAI";

interface Props {
  userId: string;
  compact?: boolean;
}

export const PolicyComplianceIndicator: FC<Props> = ({ userId, compact = false }) => {
  const { can } = usePermission();
  const { compliance, loading, refetch } = usePolicyCompliance(userId);
  const { explanation, loading: xaiLoading } = useComplianceXAI(userId);
  const [exporting, setExporting] = useState(false);
  const containerRef = useState<HTMLDivElement | null>(null)[0];

  const handleExport = async () => {
    if (!containerRef) return;
    setExporting(true);
    try {
      const canvas = await html2canvas(containerRef);
      canvas.toBlob(blob => {
        if (blob) saveAs(blob, `compliance_status_${userId}.png`);
      });
    } finally {
      setExporting(false);
    }
  };

  const getIcon = (state: string) => {
    switch (state) {
      case "compliant":
        return <CheckCircleIcon className="w-4 h-4 text-green-600" />;
      case "non-compliant":
        return <XCircleIcon className="w-4 h-4 text-red-500" />;
      case "pending":
        return <Loader2Icon className="w-4 h-4 animate-spin text-muted-foreground" />;
      default:
        return <AlertTriangleIcon className="w-4 h-4 text-yellow-500" />;
    }
  };

  const items = useMemo(() => {
    if (!compliance) return [];
    return [
      { key: "kyc", label: "KYC / Идентификация", status: compliance.kyc },
      { key: "nda", label: "Соглашение о неразглашении", status: compliance.nda },
      { key: "ethics", label: "Кодекс этики", status: compliance.ethics },
      { key: "secureCode", label: "Безопасный кодекс", status: compliance.secureCode },
      { key: "training", label: "Прохождение обучения", status: compliance.training }
    ];
  }, [compliance]);

  const completed = items.filter(i => i.status === "compliant").length;
  const total = items.length;
  const progress = Math.round((completed / total) * 100);

  if (loading || !compliance) {
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
          <CardTitle className="text-xl">Соблюдение политики</CardTitle>
          <p className="text-sm text-muted-foreground">Мониторинг ключевых требований и комплаенса</p>
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
                {getIcon(item.status)}
                <Badge variant="outline">
                  {item.status === "compliant"
                    ? "Соблюдено"
                    : item.status === "non-compliant"
                    ? "Нарушено"
                    : item.status === "pending"
                    ? "Ожидается"
                    : "Неизвестно"}
                </Badge>
              </div>
            </div>
          ))}
        </div>

        <div>
          <p className="text-sm text-muted-foreground mb-1 font-semibold">Общий комплаенс-прогресс:</p>
          <Progress value={progress} className="h-3 rounded-full" />
        </div>

        {can(Role.SUPERVISOR) && explanation && !xaiLoading && (
          <div className="mt-6">
            <XAIExplanation
              explanation={explanation}
              title="AI-пояснение несоответствий"
            />
          </div>
        )}
      </CardContent>
    </Card>
  );
};
