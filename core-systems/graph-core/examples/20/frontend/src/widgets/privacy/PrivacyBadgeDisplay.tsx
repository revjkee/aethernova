import React, { useEffect, useState, useMemo } from "react";
import { ShieldCheckIcon, EyeOffIcon, GlobeOffIcon, BotIcon, FingerprintIcon } from "lucide-react";
import { Tooltip } from "@/components/ui/tooltip";
import { motion } from "framer-motion";
import { cn } from "@/lib/utils";
import { usePrivacySettings } from "@/hooks/privacy/usePrivacySettings";
import { useEventBus } from "@/hooks/system/useEventBus";
import { PRIVACY_EVENTS } from "@/types/privacy";

type BadgeType =
  | "doNotTrack"
  | "geoFenceOff"
  | "aiTransparency"
  | "noFingerprint"
  | "privateBrowsing";

interface PrivacyBadge {
  type: BadgeType;
  label: string;
  icon: React.ReactNode;
  colorClass: string;
  description: string;
}

interface Props {
  style?: "minimal" | "detailed";
}

const BADGE_MAP: Record<BadgeType, Omit<PrivacyBadge, "type">> = {
  doNotTrack: {
    label: "DNT",
    icon: <EyeOffIcon className="w-4 h-4" />,
    colorClass: "bg-amber-600 text-white",
    description: "Запрос 'Do Not Track' активен. Трекинг отключён.",
  },
  geoFenceOff: {
    label: "Geo Off",
    icon: <GlobeOffIcon className="w-4 h-4" />,
    colorClass: "bg-blue-700 text-white",
    description: "Ограничения по геолокации активированы.",
  },
  aiTransparency: {
    label: "AI View",
    icon: <BotIcon className="w-4 h-4" />,
    colorClass: "bg-green-700 text-white",
    description: "AI-отчётность включена. Все действия логируются.",
  },
  noFingerprint: {
    label: "No Fingerprint",
    icon: <FingerprintIcon className="w-4 h-4" />,
    colorClass: "bg-purple-700 text-white",
    description: "Снятие отпечатков (браузера/устройства) отключено.",
  },
  privateBrowsing: {
    label: "Private",
    icon: <ShieldCheckIcon className="w-4 h-4" />,
    colorClass: "bg-gray-700 text-white",
    description: "Приватный режим активен. Логи не сохраняются.",
  },
};

export const PrivacyBadgeDisplay: React.FC<Props> = ({ style = "detailed" }) => {
  const { settings } = usePrivacySettings();
  const [activeBadges, setActiveBadges] = useState<BadgeType[]>([]);
  const bus = useEventBus();

  useEffect(() => {
    const enabled: BadgeType[] = [];
    if (settings?.doNotTrack) enabled.push("doNotTrack");
    if (settings?.geoFence === false) enabled.push("geoFenceOff");
    if (settings?.aiTransparency === true) enabled.push("aiTransparency");
    if (settings?.noFingerprint === true) enabled.push("noFingerprint");
    if (settings?.privateBrowsing === true) enabled.push("privateBrowsing");

    setActiveBadges(enabled);
  }, [settings]);

  useEffect(() => {
    const listener = () => {
      setActiveBadges([]);
      setTimeout(() => {
        const refreshed = [];
        if (settings?.doNotTrack) refreshed.push("doNotTrack");
        if (settings?.geoFence === false) refreshed.push("geoFenceOff");
        if (settings?.aiTransparency === true) refreshed.push("aiTransparency");
        if (settings?.noFingerprint === true) refreshed.push("noFingerprint");
        if (settings?.privateBrowsing === true) refreshed.push("privateBrowsing");
        setActiveBadges(refreshed);
      }, 150);
    };

    bus.on(PRIVACY_EVENTS.PREFERENCES_UPDATED, listener);
    return () => bus.off(PRIVACY_EVENTS.PREFERENCES_UPDATED, listener);
  }, [bus, settings]);

  const renderBadges = useMemo(
    () =>
      activeBadges.map((type) => {
        const { label, icon, colorClass, description } = BADGE_MAP[type];
        return (
          <Tooltip key={type} content={description}>
            <motion.div
              className={cn(
                "flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium shadow",
                colorClass
              )}
              initial={{ opacity: 0, scale: 0.85 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.2 }}
            >
              {icon}
              {style === "detailed" && <span>{label}</span>}
            </motion.div>
          </Tooltip>
        );
      }),
    [activeBadges, style]
  );

  if (!activeBadges.length) return null;

  return (
    <div className="flex gap-2 flex-wrap items-center justify-start">
      {renderBadges}
    </div>
  );
};

PrivacyBadgeDisplay.displayName = "PrivacyBadgeDisplay";
