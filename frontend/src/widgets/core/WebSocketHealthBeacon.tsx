import React, { useEffect, useRef, useState } from "react";
import { motion } from "framer-motion";
import { useTranslation } from "react-i18next";
import { Tooltip } from "@/components/ui/tooltip";
import { Card } from "@/components/ui/card";
import { useTheme } from "@/shared/hooks/useThemeSwitcher";
import { logWebSocketError } from "@/shared/utils/logger";
import styles from "./WebSocketHealthBeacon.module.css";

type WSStatus = "connected" | "disconnected" | "reconnecting" | "error" | "connecting";

interface WSState {
  status: WSStatus;
  latency: number | null;
  lastError?: string;
  attempts: number;
}

const STATUS_COLORS: Record<WSStatus, string> = {
  connected: "#2ecc71",
  disconnected: "#e74c3c",
  reconnecting: "#f39c12",
  error: "#c0392b",
  connecting: "#3498db",
};

const STATUS_LABELS: Record<WSStatus, string> = {
  connected: "connected",
  disconnected: "disconnected",
  reconnecting: "reconnecting",
  error: "error",
  connecting: "connecting",
};

const PING_INTERVAL = 5000;
const RECONNECT_TIMEOUT = 3000;

export const WebSocketHealthBeacon: React.FC = () => {
  const { t } = useTranslation("network");
  const { theme } = useTheme();
  const [state, setState] = useState<WSState>({
    status: "connecting",
    latency: null,
    attempts: 0,
  });

  const wsRef = useRef<WebSocket | null>(null);
  const pingRef = useRef<number | null>(null);
  const lastPingTime = useRef<number>(0);
  const reconnectTimer = useRef<NodeJS.Timeout | null>(null);

  const setupWebSocket = () => {
    if (wsRef.current) {
      wsRef.current.close();
    }

    setState((prev) => ({ ...prev, status: "connecting", attempts: prev.attempts + 1 }));

    const ws = new WebSocket(`${window.location.protocol === "https:" ? "wss" : "ws"}://${window.location.host}/ws/health`);
    wsRef.current = ws;

    ws.onopen = () => {
      setState((prev) => ({ ...prev, status: "connected", lastError: undefined }));
      ping();
      pingRef.current = window.setInterval(ping, PING_INTERVAL);
    };

    ws.onmessage = (event) => {
      if (event.data === "pong") {
        const latency = Date.now() - lastPingTime.current;
        setState((prev) => ({ ...prev, latency, status: "connected" }));
      }
    };

    ws.onerror = (err) => {
      logWebSocketError("WebSocket error", err);
      setState((prev) => ({ ...prev, status: "error", lastError: String(err) }));
    };

    ws.onclose = () => {
      if (pingRef.current) {
        clearInterval(pingRef.current);
        pingRef.current = null;
      }
      setState((prev) => ({ ...prev, status: "reconnecting" }));
      reconnectTimer.current = setTimeout(() => setupWebSocket(), RECONNECT_TIMEOUT);
    };
  };

  const ping = () => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      lastPingTime.current = Date.now();
      wsRef.current.send("ping");
    }
  };

  useEffect(() => {
    setupWebSocket();
    return () => {
      if (pingRef.current) clearInterval(pingRef.current);
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
      wsRef.current?.close();
    };
  }, []);

  const statusColor = STATUS_COLORS[state.status];
  const latencyDisplay =
    state.latency !== null ? `${state.latency}ms` : t("noLatencyData");

  return (
    <Card className={styles.container}>
      <div className={styles.header}>
        <h3>{t("websocketStatus")}</h3>
      </div>

      <Tooltip
        content={
          <div className={styles.tooltip}>
            <div><strong>{t("status")}:</strong> {t(STATUS_LABELS[state.status])}</div>
            <div><strong>{t("latency")}:</strong> {latencyDisplay}</div>
            <div><strong>{t("attempts")}:</strong> {state.attempts}</div>
            {state.lastError && (
              <div><strong>{t("lastError")}:</strong> {state.lastError}</div>
            )}
          </div>
        }
      >
        <motion.div
          className={styles.beacon}
          animate={{
            scale: state.status === "connected" ? [1, 1.15, 1] : [1, 1, 1],
          }}
          transition={{
            duration: 1.5,
            repeat: Infinity,
            ease: "easeInOut",
          }}
          style={{
            backgroundColor: statusColor,
            boxShadow: `0 0 10px ${statusColor}`,
          }}
        />
      </Tooltip>
    </Card>
  );
};
