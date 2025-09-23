import { FC, useMemo, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { ShieldCheckIcon, EyeOffIcon, AlertTriangleIcon, Loader2Icon, DownloadIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { usePrivacyStatus } from "@/features/hr-core/hooks/usePrivacyStatus";
import { usePermission } from "@/shared/hooks/usePermission";
import { Role } from "@/shared/constants/roles";
import { cn } from "@/lib/utils";
import { XAIExplanation } from "@/features/xai/components/XAIExplanation";
import { usePrivacyXAI } from "@/features/xai/hooks/usePrivacyXAI";
import html2canvas from "html2canvas";
import { saveAs } from "file-saver";

interface Props {
  candidateId: string;
  size?: "sm" | "md";
}

export const HRPrivacyStatusBadge: FC<Props> = ({ candidateId, size = "md" }) => {
  const { can } = usePermission();
  const { status, loading } = usePrivacyStatus(candidateId);
  const { explanation, loading: xaiLoading } = usePrivacyXAI(candidateId);
  const [exporting, setExporting] = useState(false);
  const containerRef = useState<HTMLDivElement | null>(null)[0];

  const handleExport = async () => {
    if (!containerRef) return;
    setExporting(true);
    try {
      const canvas = await html2canvas(containerRef);
      canvas.toBlob(blob => {
        if (blob) saveAs(blob, `privacy_status_${candidateId}.png`);
      });
    } finally {
      setExporting(false);
    }
  };

  const getColor = (state: string): string => {
    switch (state) {
      case "private":
        return "bg-green-600";
      case "semi-private":
        return "bg-yellow-400";
      case "public":
        return "bg-red-500";
      default:
        return "bg-muted";
    }
  };

  const label = useMemo(() => {
    if (!status) return "Загрузка...";
    switch (status.level) {
      case "private":
        return "Приватный";
      case "semi-private":
        return "Частично анонимизирован";
      case "public":
        return "Доступен публично";
      default:
        return "Неизвестно";
    }
  }, [status]);

  const description = useMemo(() => {
    if (!status) return "";
    return [
      status.gdprConsent ? "✔ GDPR" : "✖ GDPR",
      status.tracking ? "🛑 Слежение активно" : "✅ Без слежки",
      status.exportable ? "↗ Доступен для экспорта" : "🔒 Экспорт ограничен"
    ].join(" • ");
  }, [status]);

  if (loading || !status) {
    return (
      <Badge variant="outline" className="flex items-center gap-1">
        <Loader2Icon className="w-3 h-3 animate-spin" />
        Проверка приватности…
      </Badge>
    );
  }

  return (
    <div className="flex flex-col gap-2" ref={containerRef}>
      <TooltipProvider>
        <Tooltip delayDuration={150}>
          <TooltipTrigger asChild>
            <Badge
              className={cn(
                "inline-flex items-center gap-1",
                size === "sm" ? "text-xs px-2 py-0.5" : "text-sm px-3 py-1",
                getColor(status.level)
              )}
            >
              {status.level === "private" && <ShieldCheckIcon className="w-4 h-4" />}
              {status.level === "semi-private" && <EyeOffIcon className="w-4 h-4" />}
              {status.level === "public" && <AlertTriangleIcon className="w-4 h-4" />}
              {label}
            </Badge>
          </TooltipTrigger>
          <TooltipContent>
            <div className="max-w-xs text-sm leading-snug">
              <p>{description}</p>
              {can(Role.SUPERVISOR) && (
                <div className="mt-2 text-xs text-muted-foreground">
                  AI-риск: {status.riskScore}/100
                </div>
              )}
            </div>
          </TooltipContent>
        </Tooltip>
      </TooltipProvider>

      {can(Role.SUPERVISOR) && explanation && !xaiLoading && (
        <XAIExplanation
          explanation={explanation}
          title="AI-пояснение приватности"
        />
      )}

      {can(Role.SUPERVISOR) && (
        <Button
          variant="ghost"
          size="sm"
          onClick={handleExport}
          className="self-start text-xs"
          disabled={exporting}
        >
          <DownloadIcon className="w-3 h-3 mr-1" />
          {exporting ? "Экспорт…" : "Сохранить PNG"}
        </Button>
      )}
    </div>
  );
};
