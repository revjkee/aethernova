import { useEffect, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Logger } from "@/shared/utils/logger";
import { useTranslation } from "react-i18next";
import { cn } from "@/shared/utils/classNames";
import { trackEvent } from "@/services/analytics/tracker";
import { detectThirdPartyTrackers, blockThirdPartyTracker, unblockThirdPartyTracker } from "@/services/privacy/trackerControlService";

interface TrackerInfo {
  name: string;
  domain: string;
  status: "blocked" | "active" | "pending";
  critical?: boolean;
}

export const ThirdPartyTrackerBlocker = ({ className }: { className?: string }) => {
  const { t } = useTranslation();
  const [trackers, setTrackers] = useState<TrackerInfo[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  const fetchTrackers = async () => {
    try {
      setLoading(true);
      const detected = await detectThirdPartyTrackers();
      setTrackers(detected);
    } catch (err) {
      Logger.error("Failed to detect third-party trackers", err);
      setError(t("privacy.tracker_error"));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTrackers();
  }, []);

  const toggleBlock = async (tracker: TrackerInfo, block: boolean) => {
    try {
      const action = block ? blockThirdPartyTracker : unblockThirdPartyTracker;
      await action(tracker.domain);
      setTrackers((prev) =>
        prev.map((t) =>
          t.domain === tracker.domain ? { ...t, status: block ? "blocked" : "active" } : t
        )
      );
      trackEvent("tracker_toggle", {
        domain: tracker.domain,
        action: block ? "blocked" : "unblocked",
      });
    } catch (err) {
      Logger.error(`Failed to ${block ? "block" : "unblock"} tracker`, err);
      setError(t("privacy.tracker_toggle_error"));
    }
  };

  return (
    <div className={cn("space-y-6", className)}>
      {error && (
        <div className="text-destructive text-sm font-semibold">{error}</div>
      )}

      <Card>
        <CardHeader>
          <CardTitle>{t("privacy.tracker_title")}</CardTitle>
          <CardDescription>{t("privacy.tracker_description")}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {loading ? (
            <div className="text-sm text-muted-foreground">{t("privacy.tracker_loading")}</div>
          ) : trackers.length === 0 ? (
            <div className="text-sm text-muted-foreground">{t("privacy.no_trackers_detected")}</div>
          ) : (
            trackers.map((tracker) => (
              <div
                key={tracker.domain}
                className="flex items-center justify-between py-2 border-b last:border-b-0"
              >
                <div>
                  <div className="font-medium">{tracker.name}</div>
                  <div className="text-xs text-muted-foreground">{tracker.domain}</div>
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant={tracker.status === "blocked" ? "destructive" : "secondary"}>
                    {t(`privacy.status.${tracker.status}`)}
                  </Badge>
                  <Switch
                    checked={tracker.status === "blocked"}
                    onCheckedChange={(checked) => toggleBlock(tracker, checked)}
                    disabled={tracker.critical}
                    aria-label={`toggle-${tracker.domain}`}
                  />
                </div>
              </div>
            ))
          )}
        </CardContent>
      </Card>
    </div>
  );
};
