import { useEffect, useState } from "react";
import { Card, CardHeader, CardContent, CardTitle, CardDescription } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { useTranslation } from "react-i18next";
import { cn } from "@/shared/utils/classNames";
import { Logger } from "@/shared/utils/logger";
import { fetchComplianceScores } from "@/services/privacy/complianceAuditService";
import { Badge } from "@/components/ui/badge";
import { ShieldCheckIcon, AlertTriangleIcon } from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";

type Law =
  | "GDPR"
  | "CCPA"
  | "ZADA"
  | "LGPD"
  | "PIPEDA"
  | "DSA"
  | "FADP"
  | "PDPA"
  | "HIPAA";

interface ComplianceScore {
  law: Law;
  score: number; // 0–100
  level: "low" | "medium" | "high";
  remarks?: string;
}

export const PrivacyComplianceMeter = ({ className }: { className?: string }) => {
  const { t } = useTranslation();
  const [scores, setScores] = useState<ComplianceScore[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const load = async () => {
      try {
        const data = await fetchComplianceScores();
        setScores(data);
      } catch (err) {
        Logger.error("Failed to load compliance scores", err);
        setError(t("compliance.error_loading"));
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [t]);

  const getColor = (score: number) => {
    if (score >= 85) return "bg-green-600";
    if (score >= 50) return "bg-yellow-500";
    return "bg-red-600";
  };

  const getLabel = (level: ComplianceScore["level"]) => {
    switch (level) {
      case "high":
        return t("compliance.level_high");
      case "medium":
        return t("compliance.level_medium");
      case "low":
        return t("compliance.level_low");
    }
  };

  const renderBadge = (level: ComplianceScore["level"]) =>
    level === "high" ? (
      <Badge variant="outline" className="text-green-700 border-green-600">
        <ShieldCheckIcon className="w-3.5 h-3.5 mr-1" />
        {getLabel(level)}
      </Badge>
    ) : (
      <Badge variant="destructive">
        <AlertTriangleIcon className="w-3.5 h-3.5 mr-1" />
        {getLabel(level)}
      </Badge>
    );

  return (
    <Card className={cn("w-full", className)}>
      <CardHeader>
        <CardTitle className="text-sm sm:text-base">{t("compliance.title")}</CardTitle>
        <CardDescription>{t("compliance.description")}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {loading && (
          <div className="space-y-4">
            {[...Array(4)].map((_, i) => (
              <Skeleton key={i} className="h-5 w-full" />
            ))}
          </div>
        )}

        {error && (
          <div className="text-destructive text-sm font-medium">
            {error}
          </div>
        )}

        {scores?.map((item) => (
          <div key={item.law} className="space-y-1">
            <div className="flex items-center justify-between">
              <span className="font-medium">{t(`compliance.laws.${item.law}`)}</span>
              {renderBadge(item.level)}
            </div>
            <div className="flex items-center gap-2">
              <Progress value={item.score} className={getColor(item.score)} />
              <span className="text-xs text-muted-foreground">{item.score}%</span>
            </div>
            {item.remarks && (
              <div className="text-xs text-muted-foreground italic">
                {item.remarks}
              </div>
            )}
          </div>
        ))}
      </CardContent>
    </Card>
  );
};
