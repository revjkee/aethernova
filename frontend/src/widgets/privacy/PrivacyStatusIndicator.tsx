import React, { useEffect, useMemo, useState } from "react";
import { Tooltip, Badge } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";
import { fetchPrivacyTelemetry } from "@/services/privacy/telemetry";
import { useEventBus } from "@/hooks/system/useEventBus";
import { PRIVACY_EVENTS, PrivacyStatus, PrivacyLevel } from "@/types/privacy";
import { ShieldLockIcon, EyeOffIcon, GlobeIcon } from "lucide-react";
import { AnimatePresence, motion } from "framer-motion";
import { usePrivacyPolicy } from "@/hooks/privacy/usePrivacyPolicy";

type Props = {
  agentId?: string;
  compact?: boolean;
  withLabel?: boolean;
};

const privacyLevelColors: Record<PrivacyLevel, string> = {
  "MAX_SECURE": "bg-green-500",
  "TOR_ONLY": "bg-blue-500",
  "VPN_ONLY": "bg-yellow-500",
  "PARTIAL": "bg-orange-500",
  "INSECURE": "bg-red-500",
  "UNKNOWN": "bg-gray-400",
};

const iconMap: Record<PrivacyLevel, JSX.Element> = {
  "MAX_SECURE": <ShieldLockIcon className="w-4 h-4 text-white" />,
  "TOR_ONLY": <GlobeIcon className="w-4 h-4 text-white" />,
  "VPN_ONLY": <GlobeIcon className="w-4 h-4 text-white" />,
  "PARTIAL": <EyeOffIcon className="w-4 h-4 text-white" />,
  "INSECURE": <EyeOffIcon className="w-4 h-4 text-white" />,
  "UNKNOWN": <EyeOffIcon className="w-4 h-4 text-white" />,
};

export const PrivacyStatusIndicator: React.FC<Props> = ({
  agentId,
  compact = false,
  withLabel = false
}) => {
  const [status, setStatus] = useState<PrivacyStatus | null>(null);
  const bus = useEventBus();
  const { resolveLabel } = usePrivacyPolicy();

  const fetchStatus = async () => {
    const data = await fetchPrivacyTelemetry(agentId);
    setStatus(data);
  };

  useEffect(() => {
    fetchStatus();
    const unsubscribe = bus.subscribe(PRIVACY_EVENTS.STATUS_UPDATED, fetchStatus);
    return () => unsubscribe();
  }, [agentId]);

  const level = status?.level || "UNKNOWN";
  const label = useMemo(() => resolveLabel(level), [level]);
  const indicatorColor = privacyLevelColors[level];

  return (
    <AnimatePresence>
      <motion.div
        className={cn(
          "inline-flex items-center gap-2 px-2 py-1 rounded-xl shadow-sm",
          indicatorColor
        )}
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        exit={{ opacity: 0 }}
        transition={{ duration: 0.2 }}
      >
        <Tooltip
          content={
            <div className="text-sm">
              <strong>Privacy Level:</strong> {label}<br />
              <strong>Network:</strong> {status?.network || "N/A"}<br />
              <strong>ZK Auth:</strong> {status?.zkVerified ? "✓ Valid" : "✗ Not Verified"}
            </div>
          }
        >
          <Badge className="p-1 cursor-help" variant="ghost">
            {iconMap[level]}
          </Badge>
        </Tooltip>

        {!compact && withLabel && (
          <span className="text-white text-xs font-mono">{label}</span>
        )}
      </motion.div>
    </AnimatePresence>
  );
};

PrivacyStatusIndicator.displayName = "PrivacyStatusIndicator";
