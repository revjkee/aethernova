import React, { useEffect, useState, useCallback } from "react";
import { useToast } from "@/components/ui/use-toast";
import { Progress } from "@/components/ui/progress";
import { Button } from "@/components/ui/button";
import { formatDistanceToNowStrict, addMilliseconds } from "date-fns";
import { getUserRetentionPolicy, revokeDataAccess, prolongDataHold } from "@/services/privacy/dataRetentionService";
import { useEventBus } from "@/hooks/system/useEventBus";
import { PRIVACY_EVENTS } from "@/types/privacy";
import { motion } from "framer-motion";
import { DataKeyIcon, ShieldOffIcon, AlarmClockIcon } from "lucide-react";
import { Tooltip } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";

interface Props {
  userId: string;
  style?: "compact" | "detailed";
}

export const DataRetentionTimer: React.FC<Props> = ({ userId, style = "detailed" }) => {
  const [expiry, setExpiry] = useState<Date | null>(null);
  const [remainingPercent, setRemainingPercent] = useState<number>(100);
  const [loading, setLoading] = useState(false);
  const { toast } = useToast();
  const bus = useEventBus();

  const fetchExpiry = useCallback(async () => {
    try {
      const { expiryAt } = await getUserRetentionPolicy(userId);
      const expiryDate = new Date(expiryAt);
      setExpiry(expiryDate);
    } catch (e) {
      console.error("Ошибка загрузки политики хранения данных", e);
    }
  }, [userId]);

  const updateTimer = useCallback(() => {
    if (!expiry) return;
    const now = new Date();
    const total = expiry.getTime() - now.getTime();
    const maxWindow = 1000 * 60 * 60 * 24 * 30; // 30 дней
    setRemainingPercent(Math.max(0, Math.min(100, (total / maxWindow) * 100)));
  }, [expiry]);

  const handleRevoke = async () => {
    setLoading(true);
    try {
      await revokeDataAccess(userId);
      toast({
        title: "Доступ к данным отозван",
        description: "Персональные данные были криптографически уничтожены",
        variant: "default",
      });
      bus.emit(PRIVACY_EVENTS.DATA_ERASED, { userId });
      await fetchExpiry();
    } catch (e) {
      toast({
        title: "Ошибка при удалении данных",
        description: (e as Error)?.message || "Неизвестная ошибка",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const handleProlong = async () => {
    setLoading(true);
    try {
      const newExpiry = await prolongDataHold(userId, 7); // продление на 7 дней
      setExpiry(new Date(newExpiry));
      toast({
        title: "Срок хранения продлён",
        description: "Политика хранения была продлена на 7 дней",
      });
    } catch (e) {
      toast({
        title: "Ошибка продления",
        description: (e as Error)?.message || "Неизвестная ошибка",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchExpiry();
    const interval = setInterval(updateTimer, 60000); // 1 минута
    return () => clearInterval(interval);
  }, [fetchExpiry, updateTimer]);

  if (!expiry) return null;

  const now = new Date();
  const timeLeft = expiry.getTime() - now.getTime();
  const humanReadable = formatDistanceToNowStrict(expiry, { addSuffix: true });

  return (
    <motion.div
      className={cn(
        "border rounded-xl p-4 shadow-md bg-muted/40 flex flex-col gap-3",
        style === "compact" && "p-2"
      )}
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.3 }}
    >
      <div className="flex items-center gap-2">
        <AlarmClockIcon className="w-5 h-5 text-orange-500" />
        <span className="text-sm font-semibold text-muted-foreground">
          Хранение данных истекает {humanReadable}
        </span>
      </div>

      <Progress value={remainingPercent} className="h-2 bg-accent/20" />

      {style === "detailed" && (
        <div className="flex justify-between items-center mt-2 gap-2">
          <Tooltip content="Удалить все данные и отозвать доступ">
            <Button
              variant="destructive"
              size="sm"
              onClick={handleRevoke}
              disabled={loading}
            >
              <ShieldOffIcon className="w-4 h-4 mr-1" /> Удалить
            </Button>
          </Tooltip>

          <Tooltip content="Продлить срок хранения на 7 дней">
            <Button
              variant="secondary"
              size="sm"
              onClick={handleProlong}
              disabled={loading}
            >
              <DataKeyIcon className="w-4 h-4 mr-1" /> Продлить
            </Button>
          </Tooltip>
        </div>
      )}
    </motion.div>
  );
};

DataRetentionTimer.displayName = "DataRetentionTimer";
