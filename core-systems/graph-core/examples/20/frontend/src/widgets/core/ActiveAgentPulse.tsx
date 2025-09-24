import React, { useEffect, useMemo, useRef, useState } from "react";
import { motion, useAnimation, AnimatePresence } from "framer-motion";
import { useTranslation } from "react-i18next";
import { Tooltip } from "@/components/ui/tooltip";
import { Card } from "@/components/ui/card";
import { Spinner } from "@/shared/components/Spinner";
import { fetchAgentTelemetry } from "@/shared/api/agents";
import styles from "./ActiveAgentPulse.module.css";

interface AgentStatus {
  id: string;
  name: string;
  status: "idle" | "active" | "error" | "terminated";
  load: number;
  lastSeen: string;
  region: string;
  role: string;
  heartbeat: number;
  anomalyScore: number;
}

const STATUS_COLORS: Record<AgentStatus["status"], string> = {
  idle: "#f1c40f",
  active: "#2ecc71",
  error: "#e74c3c",
  terminated: "#7f8c8d",
};

const PULSE_SIZE = 20;

export const ActiveAgentPulse: React.FC = () => {
  const { t } = useTranslation("agent");
  const [agents, setAgents] = useState<AgentStatus[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const intervalRef = useRef<NodeJS.Timeout | null>(null);
  const animationControls = useAnimation();

  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true);
        const result = await fetchAgentTelemetry();
        setAgents(result);
      } catch (e) {
        console.error("Failed to fetch agent telemetry", e);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
    intervalRef.current = setInterval(fetchData, 5000);

    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, []);

  const pulseVariants = {
    pulse: (heartbeat: number) => ({
      scale: [1, 1.3, 1],
      transition: {
        duration: Math.max(0.3, 1.5 - heartbeat / 100),
        repeat: Infinity,
        ease: "easeInOut",
      },
    }),
  };

  const totalActive = useMemo(
    () => agents.filter((a) => a.status === "active").length,
    [agents]
  );

  if (loading) {
    return <Spinner message={t("loadingAgentPulse")} />;
  }

  return (
    <Card className={styles.container}>
      <div className={styles.header}>
        <h3>{t("activeAgentPulse")}</h3>
        <span className={styles.totalCount}>
          {t("totalActive")}: {totalActive}/{agents.length}
        </span>
      </div>

      <div className={styles.grid}>
        <AnimatePresence>
          {agents.map((agent) => (
            <Tooltip
              key={agent.id}
              content={
                <div className={styles.tooltip}>
                  <div><strong>{t("agent")}:</strong> {agent.name}</div>
                  <div><strong>{t("role")}:</strong> {agent.role}</div>
                  <div><strong>{t("region")}:</strong> {agent.region}</div>
                  <div><strong>{t("load")}:</strong> {agent.load}%</div>
                  <div><strong>{t("anomaly")}:</strong> {agent.anomalyScore.toFixed(2)}</div>
                  <div><strong>{t("lastSeen")}:</strong> {new Date(agent.lastSeen).toLocaleTimeString()}</div>
                </div>
              }
            >
              <motion.div
                className={styles.pulse}
                style={{
                  backgroundColor: STATUS_COLORS[agent.status],
                  width: PULSE_SIZE,
                  height: PULSE_SIZE,
                }}
                animate={animationControls}
                custom={agent.heartbeat}
                variants={pulseVariants}
                initial="pulse"
              />
            </Tooltip>
          ))}
        </AnimatePresence>
      </div>
    </Card>
  );
};
