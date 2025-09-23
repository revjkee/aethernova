import React, { useCallback, useEffect, useState } from "react";
import { Switch } from "@/components/ui/switch";
import { useToast } from "@/components/ui/use-toast";
import { toggleSessionTracking, getSessionTrackingState } from "@/services/privacy/sessionControl";
import { useEventBus } from "@/hooks/system/useEventBus";
import { PRIVACY_EVENTS } from "@/types/privacy";
import { motion } from "framer-motion";
import { cn } from "@/lib/utils";
import { Tooltip } from "@/components/ui/tooltip";
import { TrackIcon, TrackOffIcon } from "lucide-react";
import { useZKIdentity } from "@/hooks/privacy/useZKIdentity";

interface Props {
  agentId?: string;
  size?: "sm" | "md" | "lg";
  inlineLabel?: boolean;
}

export const SessionPrivacyToggler: React.FC<Props> = ({
  agentId,
  size = "md",
  inlineLabel = true
}) => {
  const [enabled, setEnabled] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(false);
  const { toast } = useToast();
  const bus = useEventBus();
  const { zkFingerprint, zkValid } = useZKIdentity();

  const fetchTrackingState = useCallback(async () => {
    const state = await getSessionTrackingState(agentId);
    setEnabled(state.enabled);
  }, [agentId]);

  const handleToggle = async () => {
    setLoading(true);
    try {
      const nextState = !enabled;
      await toggleSessionTracking({ agentId, enabled: nextState });
      setEnabled(nextState);

      bus.emit(PRIVACY_EVENTS.SESSION_TRACKING_TOGGLED, {
        agentId,
        enabled: nextState,
      });

      toast({
        title: `Слежение сессии ${nextState ? "включено" : "отключено"}`,
        description: nextState
          ? "Аналитика и трейсинг активности теперь разрешены."
          : "Все трекеры и session listeners выключены.",
        variant: "default",
      });
    } catch (err) {
      toast({
        title: "Ошибка переключения режима приватности",
        description: (err as Error)?.message || "Unknown error",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTrackingState();
    const unsub = bus.subscribe(PRIVACY_EVENTS.POLICY_UPDATED, fetchTrackingState);
    return () => unsub();
  }, [agentId]);

  return (
    <motion.div
      className={cn("flex items-center", {
        "gap-3": inlineLabel,
        "flex-col": !inlineLabel,
      })}
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.3 }}
    >
      <Tooltip
        content={
          enabled
            ? "Сессия отслеживается (ZK подписано)"
            : "Сессия в приватном режиме. Аналитика отключена."
        }
      >
        <Switch
          size={size}
          checked={enabled}
          onCheckedChange={handleToggle}
          disabled={loading || !zkValid}
          icon={enabled ? <TrackIcon className="w-4 h-4" /> : <TrackOffIcon className="w-4 h-4" />}
        />
      </Tooltip>
      <div className="text-xs font-mono text-muted-foreground">
        {enabled ? "Session Tracing ON" : "Private Mode"}
        {zkFingerprint && zkValid && (
          <span className="ml-2 text-green-500">(zk✓)</span>
        )}
      </div>
    </motion.div>
  );
};

SessionPrivacyToggler.displayName = "SessionPrivacyToggler";
