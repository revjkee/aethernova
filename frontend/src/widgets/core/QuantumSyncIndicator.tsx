import { useEffect, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Card, CardHeader, CardContent, CardTitle, CardDescription } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { BrainCircuitIcon, ShieldCheckIcon, AlertTriangleIcon, ClockIcon, Loader2Icon } from "lucide-react";
import { useTranslation } from "react-i18next";
import { cn } from "@/shared/utils/classNames";
import { fetchQuantumSyncStatus } from "@/services/quantum/syncStatusService";
import { Logger } from "@/shared/utils/logger";

interface QuantumSyncStatus {
  entanglementFidelity: number;    // 0–100
  teleportLatency: number;         // milliseconds
  qpuOnline: boolean;
  fallbackEngineActive: boolean;
  encryptionState: "stable" | "unstable" | "degraded";
  signatureVerified: boolean;
  lastCheck: string;
}

export const QuantumSyncIndicator = ({ className }: { className?: string }) => {
  const { t } = useTranslation();
  const [status, setStatus] = useState<QuantumSyncStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const loadStatus = async () => {
      try {
        const data = await fetchQuantumSyncStatus();
        setStatus(data);
      } catch (err) {
        Logger.error("Quantum sync fetch failed", err);
        setError(t("quantum.sync_error"));
      } finally {
        setLoading(false);
      }
    };
    loadStatus();
  }, [t]);

  const getFidelityColor = (val: number) => {
    if (val >= 95) return "bg-green-600";
    if (val >= 80) return "bg-yellow-500";
    return "bg-red-600";
  };

  const renderEncryptionBadge = () => {
    switch (status?.encryptionState) {
      case "stable":
        return (
          <Badge variant="outline" className="text-green-700 border-green-600">
            <ShieldCheckIcon className="w-3.5 h-3.5 mr-1" />
            {t("quantum.encryption_stable")}
          </Badge>
        );
      case "unstable":
        return (
          <Badge variant="warning">
            <AlertTriangleIcon className="w-3.5 h-3.5 mr-1" />
            {t("quantum.encryption_unstable")}
          </Badge>
        );
      case "degraded":
        return (
          <Badge variant="destructive">
            <AlertTriangleIcon className="w-3.5 h-3.5 mr-1" />
            {t("quantum.encryption_degraded")}
          </Badge>
        );
    }
  };

  const renderQPUStatus = () =>
    status?.qpuOnline ? (
      <Badge variant="outline" className="text-blue-700 border-blue-600">
        <BrainCircuitIcon className="w-3.5 h-3.5 mr-1" />
        {t("quantum.qpu_online")}
      </Badge>
    ) : (
      <Badge variant="destructive">{t("quantum.qpu_offline")}</Badge>
    );

  return (
    <Card className={cn("w-full", className)}>
      <CardHeader>
        <CardTitle className="text-sm sm:text-base">
          {t("quantum.sync_status")}
        </CardTitle>
        <CardDescription>
          {t("quantum.last_checked")}:{" "}
          <span className="font-mono text-muted-foreground">{status?.lastCheck || "—"}</span>
        </CardDescription>
      </CardHeader>

      <CardContent className="space-y-5">
        {loading && (
          <div className="space-y-3">
            {[...Array(5)].map((_, i) => (
              <Skeleton key={i} className="h-5 w-full" />
            ))}
          </div>
        )}

        {error && <div className="text-destructive text-sm">{error}</div>}

        {status && (
          <>
            <div className="flex justify-between items-center">
              <span className="text-sm font-medium">{t("quantum.qpu")}</span>
              {renderQPUStatus()}
            </div>

            <div className="space-y-1">
              <div className="flex justify-between items-center">
                <span className="text-sm font-medium">{t("quantum.fidelity")}</span>
                <span className="text-xs font-mono text-muted-foreground">{status.entanglementFidelity}%</span>
              </div>
              <Progress value={status.entanglementFidelity} className={getFidelityColor(status.entanglementFidelity)} />
            </div>

            <div className="flex justify-between items-center">
              <span className="text-sm font-medium">{t("quantum.latency")}</span>
              <Badge variant="secondary" className="font-mono">
                {status.teleportLatency}ms
              </Badge>
            </div>

            <div className="flex justify-between items-center">
              <span className="text-sm font-medium">{t("quantum.encryption")}</span>
              {renderEncryptionBadge()}
            </div>

            <div className="flex justify-between items-center">
              <span className="text-sm font-medium">{t("quantum.signature")}</span>
              {status.signatureVerified ? (
                <Badge variant="success">{t("quantum.signature_ok")}</Badge>
              ) : (
                <Badge variant="destructive">{t("quantum.signature_fail")}</Badge>
              )}
            </div>

            <div className="flex justify-between items-center">
              <span className="text-sm font-medium">{t("quantum.fallback_engine")}</span>
              <Badge variant={status.fallbackEngineActive ? "secondary" : "outline"}>
                {status.fallbackEngineActive ? t("quantum.fallback_enabled") : t("quantum.fallback_off")}
              </Badge>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
};
