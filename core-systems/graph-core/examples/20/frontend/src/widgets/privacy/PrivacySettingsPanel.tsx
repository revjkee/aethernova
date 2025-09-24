import { useEffect, useState } from "react";
import { Switch } from "@/components/ui/switch";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { useTranslation } from "react-i18next";
import { cn } from "@/shared/utils/classNames";
import { getPrivacySettings, updatePrivacySetting } from "@/services/api/privacyService";
import { Logger } from "@/shared/utils/logger";
import { trackEvent } from "@/services/analytics/tracker";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

type PrivacySettingKey =
  | "telemetry"
  | "cookies"
  | "biometric"
  | "dapp_permissions"
  | "zero_knowledge_protection"
  | "kyc_data_control"
  | "web_manifest_visibility"
  | "data_export_enabled";

interface PrivacySettings {
  [key: string]: boolean;
}

export const PrivacySettingsPanel = ({ className }: { className?: string }) => {
  const { t } = useTranslation();
  const [settings, setSettings] = useState<PrivacySettings>({});
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  const keys: { key: PrivacySettingKey; title: string; description: string }[] = [
    {
      key: "telemetry",
      title: t("privacy.telemetry_title"),
      description: t("privacy.telemetry_description"),
    },
    {
      key: "cookies",
      title: t("privacy.cookies_title"),
      description: t("privacy.cookies_description"),
    },
    {
      key: "biometric",
      title: t("privacy.biometric_title"),
      description: t("privacy.biometric_description"),
    },
    {
      key: "dapp_permissions",
      title: t("privacy.dapp_title"),
      description: t("privacy.dapp_description"),
    },
    {
      key: "zero_knowledge_protection",
      title: t("privacy.zk_title"),
      description: t("privacy.zk_description"),
    },
    {
      key: "kyc_data_control",
      title: t("privacy.kyc_title"),
      description: t("privacy.kyc_description"),
    },
    {
      key: "web_manifest_visibility",
      title: t("privacy.manifest_title"),
      description: t("privacy.manifest_description"),
    },
    {
      key: "data_export_enabled",
      title: t("privacy.export_title"),
      description: t("privacy.export_description"),
    },
  ];

  useEffect(() => {
    const load = async () => {
      try {
        const response = await getPrivacySettings();
        setSettings(response);
      } catch (err) {
        Logger.error("Failed to load privacy settings", err);
        setError(t("privacy.error_loading"));
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [t]);

  const handleToggle = async (key: PrivacySettingKey, value: boolean) => {
    try {
      setSettings((prev) => ({ ...prev, [key]: value }));
      await updatePrivacySetting(key, value);
      trackEvent("privacy_setting_changed", { key, value });
    } catch (err) {
      Logger.error(`Failed to update setting ${key}`, err);
      setError(t("privacy.error_update"));
    }
  };

  if (loading) return null;

  return (
    <div className={cn("grid gap-6", className)}>
      {error && (
        <Alert variant="destructive">
          <AlertTitle>{t("privacy.error_title")}</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      {keys.map(({ key, title, description }) => (
        <Card key={key}>
          <CardHeader className="flex flex-row items-center justify-between gap-4">
            <div className="space-y-1">
              <CardTitle className="text-sm sm:text-base">{title}</CardTitle>
              <CardDescription className="text-xs text-muted-foreground">{description}</CardDescription>
            </div>
            <Switch
              checked={settings[key]}
              onCheckedChange={(val) => handleToggle(key, val)}
              aria-label={title}
            />
          </CardHeader>
          <CardContent />
        </Card>
      ))}
    </div>
  );
};
