import React, { useMemo } from "react";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
  Legend,
  Label
} from "recharts";
import { usePrivacyScoreData } from "@/shared/hooks/usePrivacyScoreData";
import { useTheme } from "@/shared/hooks/useThemeSwitcher";
import { getPrivacyRiskColor, getPrivacyRiskLabel } from "@/shared/utils/privacyUtils";
import { Spinner } from "@/shared/components/Spinner";
import { Card } from "@/components/ui/card";
import { useTranslation } from "react-i18next";
import styles from "./AIPrivacyScoreGraph.module.css";

interface PrivacyScorePoint {
  timestamp: string;
  score: number;
  metric: string;
  anomaly: boolean;
  confidence: number;
}

const PrivacyRiskBands = [
  { label: "Safe", max: 30, color: "#2ecc71" },
  { label: "Moderate", max: 60, color: "#f1c40f" },
  { label: "Danger", max: 85, color: "#e67e22" },
  { label: "Critical", max: 100, color: "#e74c3c" },
];

export const AIPrivacyScoreGraph: React.FC = () => {
  const { data, loading, error } = usePrivacyScoreData();
  const { theme } = useTheme();
  const { t } = useTranslation("privacy");

  const chartData = useMemo(() => {
    if (!data) return [];
    return data.map((point): PrivacyScorePoint => ({
      timestamp: new Date(point.timestamp).toLocaleTimeString(),
      score: point.score,
      metric: point.metric,
      anomaly: point.anomaly,
      confidence: point.confidence,
    }));
  }, [data]);

  if (loading) {
    return <Spinner message={t("loadingPrivacyScores")} />;
  }

  if (error || !chartData.length) {
    return (
      <div className={styles.errorContainer}>
        {t("privacyScoreLoadError")}
      </div>
    );
  }

  return (
    <Card className={styles.container}>
      <h3 className={styles.header}>{t("aiPrivacyScoreGraph")}</h3>
      <ResponsiveContainer width="100%" height={400}>
        <LineChart data={chartData} margin={{ top: 30, right: 30, left: 20, bottom: 30 }}>
          <CartesianGrid strokeDasharray="3 3" stroke={theme === "dark" ? "#555" : "#ccc"} />
          <XAxis dataKey="timestamp" angle={-35} textAnchor="end" height={70}>
            <Label value={t("timestamp")} offset={-5} position="insideBottom" />
          </XAxis>
          <YAxis domain={[0, 100]}>
            <Label value={t("score")} angle={-90} position="insideLeft" />
          </YAxis>
          <Tooltip
            formatter={(value: number, name: string) =>
              [`${value}`, name === "score" ? t("score") : name]
            }
            labelFormatter={(label: string) => t("time") + ": " + label}
          />
          <Legend verticalAlign="top" height={36} />
          {PrivacyRiskBands.map((band, index) => (
            <ReferenceLine
              key={band.label}
              y={band.max}
              stroke={band.color}
              strokeDasharray="3 3"
              label={{
                value: t(`risk.${band.label.toLowerCase()}`),
                position: "right",
                fill: band.color,
              }}
            />
          ))}
          <Line
            type="monotone"
            dataKey="score"
            stroke="#3498db"
            strokeWidth={2.5}
            activeDot={{ r: 6 }}
            dot={({ cx, cy, payload }) =>
              payload.anomaly ? (
                <circle cx={cx} cy={cy} r={5} stroke="#e74c3c" strokeWidth={2} fill="#fff" />
              ) : null
            }
          />
        </LineChart>
      </ResponsiveContainer>
      <div className={styles.legendBox}>
        {PrivacyRiskBands.map((band) => (
          <div key={band.label} className={styles.legendItem}>
            <span
              className={styles.colorBox}
              style={{ backgroundColor: band.color }}
            />
            <span>{t(`risk.${band.label.toLowerCase()}`)}</span>
          </div>
        ))}
      </div>
    </Card>
  );
};
