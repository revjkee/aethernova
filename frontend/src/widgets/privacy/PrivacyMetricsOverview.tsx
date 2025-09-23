import { useEffect, useState } from "react";
import { Card, CardHeader, CardContent, CardTitle, CardDescription } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { ShieldCheckIcon, AlertCircleIcon, LoaderIcon } from "lucide-react";
import { useTranslation } from "react-i18next";
import { fetchPrivacyMetrics } from "@/services/privacy/privacyMetricsService";
import { Logger } from "@/shared/utils/logger";
import { cn } from "@/shared/utils/classNames";

interface PrivacyMetrics {
  fingerprintRisk: number; // 0–100
  trackerCount: number;
  kycLinked: boolean;
  web3Identified: boolean;
  dataLeakDetected: boolean;
  behaviorProfileActive: boolean;
  complianceScore: number; // 0–100
  timestamp: string;
}

export const PrivacyMetricsOverview = ({ className }: { className?: string }) => {
  const { t } = useTranslation();
  const [metrics, setMetrics] = useState<PrivacyMetrics | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const loadMetrics = async () => {
      try {
        const data = await fetchPrivacyMetrics();
        setMetrics(data);
      } catch (err) {
        Logger.error("Failed to fetch privacy metrics", err);
        setError(t("privacy_metrics.error_loading"));
      } finally {
        setLoading(false);
      }
    };

    loadMetrics();
  }, [t]);

  const getRiskColor = (value: number) => {
    if (value >= 75) return "bg-red-600";
    if (value >= 40) return "bg-yellow-500";
    return "bg-green-600";
  };

  const renderBooleanBadge = (val: boolean, labelOn: string, labelOff: string) =>
    val ? (
      <Badge variant="destructive">
        <AlertCircleIcon className="w-3.5 h-3.5 mr-1" />
        {labelOn}
      </Badge>
    ) : (
      <Badge variant="outline" className="text-green-700 border-green-600">
        <ShieldCheckIcon className="w-3.5 h-3.5 mr-1" />
        {labelOff}
      </Badge>
    );

  return (
    <Card className={cn("w-full", className)}>
      <CardHeader>
        <CardTitle className="text-sm sm:text-base">
          {t("privacy_metrics.title")}
        </CardTitle>
        <CardDescription>
          {t("privacy_metrics.last_updated")}:{" "}
          <span className="text-muted-foreground font-mono">
            {metrics?.timestamp || "—"}
          </span>
        </CardDescription>
      </CardHeader>

      <CardContent className="space-y-5">
        {loading && (
          <div className="space-y-4">
            {[...Array(6)].map((_, i) => (
              <Skeleton key={i} className="h-5 w-full" />
            ))}
          </div>
        )}

        {error && (
          <div className="text-destructive font-medium text-sm">{error}</div>
        )}

        {metrics && (
          <>
            <div className="space-y-1">
              <div className="flex justify-between items-center">
                <span className="text-sm font-medium">
                  {t("privacy_metrics.fingerprint_risk")}
                </span>
                <span className="text-xs text-muted-foreground">
                  {metrics.fingerprintRisk}/100
                </span>
              </div>
              <Progress value={metrics.fingerprintRisk} className={getRiskColor(metrics.fingerprintRisk)} />
            </div>

            <div className="flex justify-between items-center">
              <span className="text-sm font-medium">
                {t("privacy_metrics.trackers")}
              </span>
              <Badge variant={metrics.trackerCount > 5 ? "destructive" : "secondary"}>
                {metrics.trackerCount} {t("privacy_metrics.trackers_count")}
              </Badge>
            </div>

            <div className="flex justify-between items-center">
              <span className="text-sm font-medium">
                {t("privacy_metrics.kyc")}
              </span>
              {renderBooleanBadge(
                metrics.kycLinked,
                t("privacy_metrics.linked"),
                t("privacy_metrics.not_linked")
              )}
            </div>

            <div className="flex justify-between items-center">
              <span className="text-sm font-medium">
                {t("privacy_metrics.web3")}
              </span>
              {renderBooleanBadge(
                metrics.web3Identified,
                t("privacy_metrics.exposed"),
                t("privacy_metrics.safe")
              )}
            </div>

            <div className="flex justify-between items-center">
              <span className="text-sm font-medium">
                {t("privacy_metrics.leaks")}
              </span>
              {renderBooleanBadge(
                metrics.dataLeakDetected,
                t("privacy_metrics.detected"),
                t("privacy_metrics.none")
              )}
            </div>

            <div className="flex justify-between items-center">
              <span className="text-sm font-medium">
                {t("privacy_metrics.behavior")}
              </span>
              {renderBooleanBadge(
                metrics.behaviorProfileActive,
                t("privacy_metrics.present"),
                t("privacy_metrics.none")
              )}
            </div>

            <div className="space-y-1 pt-4">
              <div className="flex justify-between items-center">
                <span className="text-sm font-medium">
                  {t("privacy_metrics.compliance_score")}
                </span>
                <span className="text-xs text-muted-foreground">
                  {metrics.complianceScore}%
                </span>
              </div>
              <Progress
                value={metrics.complianceScore}
                className={getRiskColor(100 - metrics.complianceScore)}
              />
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
};
