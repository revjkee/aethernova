import { FC } from "react";
import { Badge } from "@/components/ui/badge";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { useReferralInfo } from "@/features/hr-core/hooks/useReferralInfo";
import { usePermission } from "@/shared/hooks/usePermission";
import { Role } from "@/shared/constants/roles";
import { ShieldCheckIcon, ShieldAlertIcon, InfoIcon, DownloadIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useXAIExplanation } from "@/features/xai/hooks/useXAIExplanation";
import { XAIExplanation } from "@/features/xai/components/XAIExplanation";
import html2canvas from "html2canvas";
import { saveAs } from "file-saver";

interface Props {
  candidateId: string;
  standalone?: boolean;
}

const referralColorMap: Record<string, string> = {
  internal: "bg-green-600",
  external: "bg-blue-600",
  partner: "bg-violet-600",
  unknown: "bg-muted"
};

export const ReferralInfoTag: FC<Props> = ({ candidateId, standalone = false }) => {
  const { can } = usePermission();
  const { referral, loading } = useReferralInfo(candidateId);
  const { explanation, loading: xaiLoading } = useXAIExplanation(candidateId, "referral_origin");

  const handleExport = async () => {
    const element = document.getElementById(`referral-card-${candidateId}`);
    if (!element) return;

    const canvas = await html2canvas(element);
    canvas.toBlob((blob) => {
      if (blob) saveAs(blob, `referral_${candidateId}.png`);
    });
  };

  if (loading || !referral) {
    return standalone ? (
      <Card>
        <CardHeader>
          <Skeleton className="h-6 w-48 mb-2" />
        </CardHeader>
        <CardContent>
          <Skeleton className="h-[60px] w-full" />
        </CardContent>
      </Card>
    ) : (
      <Badge variant="secondary">
        <Skeleton className="w-24 h-4" />
      </Badge>
    );
  }

  const badgeColor = referralColorMap[referral.type] || referralColorMap.unknown;

  if (!standalone) {
    return (
      <Badge className={cn("text-white", badgeColor)}>
        Реферал: {referral.sourceLabel}
      </Badge>
    );
  }

  return (
    <Card id={`referral-card-${candidateId}`} className="transition-shadow hover:shadow-md">
      <CardHeader className="flex flex-col md:flex-row justify-between md:items-center">
        <div>
          <CardTitle className="text-xl">Реферальная информация</CardTitle>
          <p className="text-sm text-muted-foreground">Источник и верификация рекомендаций</p>
        </div>
        <div className="flex gap-2 mt-4 md:mt-0">
          {can(Role.SUPERVISOR) && (
            <Button variant="outline" size="sm" onClick={handleExport}>
              <DownloadIcon className="w-4 h-4 mr-2" />
              Сохранить PNG
            </Button>
          )}
        </div>
      </CardHeader>

      <CardContent className="space-y-4">
        <div className="flex items-center gap-4">
          <Badge className={cn("text-white", badgeColor)}>
            Тип: {referral.type.toUpperCase()}
          </Badge>

          {referral.verified ? (
            <ShieldCheckIcon className="text-green-600 w-5 h-5" />
          ) : (
            <ShieldAlertIcon className="text-red-600 w-5 h-5" />
          )}

          <span className="text-sm text-muted-foreground">
            {referral.verified ? "Проверено" : "Не верифицировано"}
          </span>
        </div>

        <div className="text-sm text-muted-foreground">
          <p>Источник: {referral.sourceLabel}</p>
          <p>Реферер: {referral.referredBy || "—"}</p>
          <p>Дата подачи: {new Date(referral.createdAt).toLocaleString()}</p>
        </div>

        {can(Role.SUPERVISOR) && explanation && !xaiLoading && (
          <div className="mt-4">
            <XAIExplanation explanation={explanation} title="AI-пояснение типа рекомендации" />
          </div>
        )}
      </CardContent>
    </Card>
  );
};
