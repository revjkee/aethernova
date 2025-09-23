import { useEffect, useState } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { getAnonymityScore } from "@/services/privacy/anonymityScoreService";
import { Logger } from "@/shared/utils/logger";
import { cn } from "@/shared/utils/classNames";
import { useTranslation } from "react-i18next";
import { ShieldCheckIcon, AlertCircleIcon } from "lucide-react";

interface AnonymityScore {
  score: number; // 0 to 100
  level: "low" | "medium" | "high";
  fingerprintDetected: boolean;
  kycLinked: boolean;
  web3Linked: boolean;
  thirdPartyCookies: boolean;
  behavioralProfilePresent: boolean;
}

export const AnonymityScoreWidget = ({ className }: { className?: string }) => {
  const { t } = useTranslation();
  const [scoreData, setScoreData] = useState<AnonymityScore | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const load = async () => {
      try {
        setLoading(true);
        const data = await getAnonymityScore();
        setScoreData(data);
      } catch (err) {
        Logger.error("Failed to fetch anonymity score", err);
        setError(t("anonymity.error_loading"));
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

  const getLabel = (level: AnonymityScore["level"]) => {
    switch (level) {
      case "high":
        return t("anonymity.high");
      case "medium":
        return t("anonymity.medium");
      case "low":
        return t("anonymity.low");
    }
  };

  return (
    <Card className={cn("w-full", className)}>
      <CardHeader className="flex items-center justify-between">
        <CardTitle className="text-sm sm:text-base">
          {t("anonymity.title")}
        </CardTitle>
        {scoreData?.level === "high" ? (
          <Badge variant="outline" className="text-green-700 border-green-600">
            <ShieldCheckIcon className="w-3.5 h-3.5 mr-1" />
            {getLabel(scoreData.level)}
          </Badge>
        ) : (
          <Badge variant="destructive">
            <AlertCircleIcon className="w-3.5 h-3.5 mr-1" />
            {getLabel(scoreData?.level || "low")}
          </Badge>
        )}
      </CardHeader>
      <CardContent className="space-y-4">
        {loading || !scoreData ? (
          <Skeleton className="h-5 w-full" />
        ) : (
          <>
            <div className="text-2xl font-bold">
              {scoreData.score}/100
            </div>
            <Progress
              value={scoreData.score}
              className={getColor(scoreData.score)}
            />
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 pt-2 text-xs text-muted-foreground">
              <div>
                {t("anonymity.fingerprint")}:{" "}
                {scoreData.fingerprintDetected ? t("anonymity.yes") : t("anonymity.no")}
              </div>
              <div>
                {t("anonymity.kyc")}:{" "}
                {scoreData.kycLinked ? t("anonymity.linked") : t("anonymity.not_linked")}
              </div>
              <div>
                {t("anonymity.web3")}:{" "}
                {scoreData.web3Linked ? t("anonymity.exposed") : t("anonymity.safe")}
              </div>
              <div>
                {t("anonymity.cookies")}:{" "}
                {scoreData.thirdPartyCookies ? t("anonymity.present") : t("anonymity.blocked")}
              </div>
              <div>
                {t("anonymity.behavior")}:{" "}
                {scoreData.behavioralProfilePresent ? t("anonymity.present") : t("anonymity.none")}
              </div>
            </div>
          </>
        )}
        {error && (
          <div className="text-xs text-destructive font-medium">
            {error}
          </div>
        )}
      </CardContent>
    </Card>
  );
};
