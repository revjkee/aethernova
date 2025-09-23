import { useEffect, useState } from "react";
import { Card, CardHeader, CardContent, CardTitle, CardDescription } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { RefreshCwIcon, ShieldCheckIcon, XOctagonIcon, BrainIcon, ActivityIcon } from "lucide-react";
import { useTranslation } from "react-i18next";
import { cn } from "@/shared/utils/classNames";
import { fetchGeniusCoreStatus } from "@/services/core/geniusCoreMonitor";
import { Logger } from "@/shared/utils/logger";

interface GeniusCoreStatusMetrics {
  coreAlive: boolean;
  intentResolver: "idle" | "resolving" | "error";
  contradictionChecker: boolean;
  heartbeat: number; // milliseconds
  activeAgents: number;
  maxAgents: number;
  jailkeeperStatus: "secure" | "compromised" | "unverified";
  zeroTrustLevel: number; // 0–100
  reasoningChainDepth: number;
  lastSync: string;
}

export const GeniusCoreStatus = ({ className }: { className?: string }) => {
  const { t } = useTranslation();
  const [metrics, setMetrics] = useState<GeniusCoreStatusMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const loadStatus = async () => {
      try {
        const data = await fetchGeniusCoreStatus();
        setMetrics(data);
      } catch (err) {
        Logger.error("Failed to load GeniusCore status", err);
        setError(t("genius_core.error"));
      } finally {
        setLoading(false);
      }
    };
    loadStatus();
  }, [t]);

  const renderStatusBadge = (status: "idle" | "resolving" | "error") => {
    switch (status) {
      case "idle":
        return <Badge variant="secondary">{t("genius_core.intent_idle")}</Badge>;
      case "resolving":
        return (
          <Badge className="bg-blue-600 text-white">
            <RefreshCwIcon className="w-3.5 h-3.5 mr-1 animate-spin" />
            {t("genius_core.intent_resolving")}
          </Badge>
        );
      case "error":
        return (
          <Badge variant="destructive">
            <XOctagonIcon className="w-3.5 h-3.5 mr-1" />
            {t("genius_core.intent_error")}
          </Badge>
        );
    }
  };

  const renderJailkeeperBadge = (status: GeniusCoreStatusMetrics["jailkeeperStatus"]) => {
    switch (status) {
      case "secure":
        return (
          <Badge variant="outline" className="text-green-700 border-green-700">
            <ShieldCheckIcon className="w-3.5 h-3.5 mr-1" />
            {t("genius_core.jailkeeper_secure")}
          </Badge>
        );
      case "compromised":
        return (
          <Badge variant="destructive">
            <XOctagonIcon className="w-3.5 h-3.5 mr-1" />
            {t("genius_core.jailkeeper_compromised")}
          </Badge>
        );
      case "unverified":
        return (
          <Badge variant="secondary">
            {t("genius_core.jailkeeper_unverified")}
          </Badge>
        );
    }
  };

  return (
    <Card className={cn("w-full", className)}>
      <CardHeader>
        <CardTitle className="text-sm sm:text-base">
          {t("genius_core.title")}
        </CardTitle>
        <CardDescription>
          {t("genius_core.last_sync")}:{" "}
          <span className="font-mono text-muted-foreground">{metrics?.lastSync || "—"}</span>
        </CardDescription>
      </CardHeader>

      <CardContent className="space-y-5">
        {loading && (
          <div className="space-y-3">
            {[...Array(6)].map((_, i) => (
              <Skeleton key={i} className="h-5 w-full" />
            ))}
          </div>
        )}

        {error && (
          <div className="text-destructive text-sm font-medium">{error}</div>
        )}

        {metrics && (
          <>
            <div className="flex justify-between items-center">
              <span className="text-sm font-medium">{t("genius_core.status")}</span>
              {metrics.coreAlive ? (
                <Badge variant="outline" className="text-green-700 border-green-600">
                  <BrainIcon className="w-3.5 h-3.5 mr-1" />
                  {t("genius_core.alive")}
                </Badge>
              ) : (
                <Badge variant="destructive">{t("genius_core.dead")}</Badge>
              )}
            </div>

            <div className="flex justify-between items-center">
              <span className="text-sm font-medium">{t("genius_core.intent")}</span>
              {renderStatusBadge(metrics.intentResolver)}
            </div>

            <div className="flex justify-between items-center">
              <span className="text-sm font-medium">{t("genius_core.contradiction")}</span>
              {metrics.contradictionChecker ? (
                <Badge variant="secondary">{t("genius_core.clean")}</Badge>
              ) : (
                <Badge variant="destructive">{t("genius_core.conflicted")}</Badge>
              )}
            </div>

            <div className="flex justify-between items-center">
              <span className="text-sm font-medium">{t("genius_core.heartbeat")}</span>
              <Badge variant="outline" className="font-mono">
                {metrics.heartbeat}ms
              </Badge>
            </div>

            <div className="flex justify-between items-center">
              <span className="text-sm font-medium">{t("genius_core.agents")}</span>
              <Badge variant="secondary">
                {metrics.activeAgents} / {metrics.maxAgents}
              </Badge>
            </div>

            <div className="flex justify-between items-center">
              <span className="text-sm font-medium">{t("genius_core.reasoning_depth")}</span>
              <Badge variant="outline" className="font-mono">
                {metrics.reasoningChainDepth}
              </Badge>
            </div>

            <div className="flex justify-between items-center">
              <span className="text-sm font-medium">{t("genius_core.jailkeeper")}</span>
              {renderJailkeeperBadge(metrics.jailkeeperStatus)}
            </div>

            <div className="space-y-1">
              <div className="flex justify-between items-center">
                <span className="text-sm font-medium">{t("genius_core.zero_trust")}</span>
                <span className="text-xs text-muted-foreground font-mono">
                  {metrics.zeroTrustLevel}%
                </span>
              </div>
              <Progress value={metrics.zeroTrustLevel} className="bg-green-600" />
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
};
