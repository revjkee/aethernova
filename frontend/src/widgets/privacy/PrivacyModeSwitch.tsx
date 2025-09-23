import { useState, useEffect } from "react";
import { Switch } from "@/components/ui/switch";
import { Card, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { cn } from "@/shared/utils/classNames";
import { useTranslation } from "react-i18next";
import { applyPrivacyMode, getPrivacyMode } from "@/services/privacy/privacyModeManager";
import { Logger } from "@/shared/utils/logger";
import { trackEvent } from "@/services/analytics/tracker";
import { Badge } from "@/components/ui/badge";
import { LockIcon, EyeOffIcon } from "lucide-react";

type PrivacyMode = "standard" | "anonymous";

export const PrivacyModeSwitch = ({ className }: { className?: string }) => {
  const { t } = useTranslation();
  const [mode, setMode] = useState<PrivacyMode>("standard");
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const load = async () => {
      try {
        const currentMode = await getPrivacyMode();
        setMode(currentMode);
      } catch (err) {
        Logger.error("Failed to fetch privacy mode", err);
        setError(t("privacy_mode.error_loading"));
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [t]);

  const handleToggle = async (enabled: boolean) => {
    const newMode: PrivacyMode = enabled ? "anonymous" : "standard";
    try {
      setMode(newMode);
      await applyPrivacyMode(newMode);
      trackEvent("privacy_mode_toggled", { mode: newMode });
    } catch (err) {
      Logger.error("Failed to toggle privacy mode", err);
      setError(t("privacy_mode.error_toggle"));
    }
  };

  if (loading) return null;

  return (
    <Card className={cn("w-full", className)}>
      <CardHeader className="flex flex-row justify-between items-center gap-4">
        <div className="space-y-1">
          <CardTitle className="text-sm sm:text-base">{t("privacy_mode.title")}</CardTitle>
          <CardDescription className="text-xs text-muted-foreground">
            {mode === "anonymous"
              ? t("privacy_mode.description_anonymous")
              : t("privacy_mode.description_standard")}
          </CardDescription>
        </div>
        <div className="flex items-center gap-3">
          <Badge
            variant={mode === "anonymous" ? "outline" : "secondary"}
            className="px-2 py-0.5 text-xs"
          >
            {mode === "anonymous" ? (
              <span className="flex items-center gap-1">
                <EyeOffIcon className="w-3.5 h-3.5" />
                {t("privacy_mode.anonymous")}
              </span>
            ) : (
              <span className="flex items-center gap-1">
                <LockIcon className="w-3.5 h-3.5" />
                {t("privacy_mode.standard")}
              </span>
            )}
          </Badge>
          <Switch
            checked={mode === "anonymous"}
            onCheckedChange={handleToggle}
            aria-label={t("privacy_mode.toggle_label")}
          />
        </div>
      </CardHeader>
    </Card>
  );
};
