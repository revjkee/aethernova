import React, { useEffect, useState, useCallback } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { useTranslation } from "react-i18next";
import { fetchLiveAlerts, subscribeAlertStream } from "@/shared/api/alerts";
import { AlertType, AlertPriority, AlertPayload } from "@/shared/types/alerts";
import { useTheme } from "@/shared/hooks/useThemeSwitcher";
import styles from "./RealTimeAlertOverlay.module.css";

const AUTO_DISMISS_TIME = 8000;
const MAX_VISIBLE_ALERTS = 5;

interface AlertState extends AlertPayload {
  id: string;
  timestamp: string;
  visible: boolean;
}

export const RealTimeAlertOverlay: React.FC = () => {
  const { t } = useTranslation("alerts");
  const { theme } = useTheme();
  const [alerts, setAlerts] = useState<AlertState[]>([]);

  const injectAlert = useCallback((alert: AlertPayload) => {
    const newAlert: AlertState = {
      ...alert,
      id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      visible: true,
    };

    setAlerts((prev) => {
      const limited = prev.filter((a) => a.visible).slice(0, MAX_VISIBLE_ALERTS - 1);
      return [newAlert, ...limited];
    });

    setTimeout(() => {
      setAlerts((prev) =>
        prev.map((a) => (a.id === newAlert.id ? { ...a, visible: false } : a))
      );
    }, AUTO_DISMISS_TIME);
  }, []);

  useEffect(() => {
    // Initial pull (in case WebSocket missed)
    fetchLiveAlerts().then((initialAlerts) => {
      initialAlerts.forEach((a) => injectAlert(a));
    });

    // Live stream subscription (WebSocket or SSE)
    const unsubscribe = subscribeAlertStream((alert) => {
      injectAlert(alert);
    });

    return () => {
      unsubscribe?.();
    };
  }, [injectAlert]);

  const priorityColor = (priority: AlertPriority): string => {
    switch (priority) {
      case "critical":
        return "#e74c3c";
      case "high":
        return "#e67e22";
      case "medium":
        return "#f1c40f";
      case "low":
        return "#3498db";
      default:
        return "#95a5a6";
    }
  };

  return (
    <div className={styles.overlayContainer}>
      <AnimatePresence initial={false}>
        {alerts.filter((a) => a.visible).map((alert) => (
          <motion.div
            key={alert.id}
            className={styles.alertBox}
            initial={{ opacity: 0, y: -40 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -40 }}
            transition={{ duration: 0.4, ease: "easeOut" }}
            style={{
              borderLeft: `4px solid ${priorityColor(alert.priority)}`,
              backgroundColor: theme === "dark" ? "#1e1e1e" : "#ffffff",
              color: theme === "dark" ? "#f4f4f4" : "#333333",
            }}
          >
            <div className={styles.alertTitle}>
              [{t(`priority.${alert.priority}`)}] {t(`type.${alert.type}`)}
            </div>
            <div className={styles.alertMessage}>{alert.message}</div>
            <div className={styles.alertTimestamp}>
              {new Date(alert.timestamp).toLocaleTimeString()}
            </div>
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  );
};
