import React, { useMemo } from "react"
import { useAlertsData } from "@/services/alerts/useAlertsData"
import { Card } from "@/shared/components/Card"
import { ProgressBar } from "@/shared/components/ProgressBar"
import { AlertSeverity } from "@/types/monitoring"
import { Tooltip } from "@/shared/components/Tooltip"
import { cn } from "@/shared/utils/style"
import { AlertIcon } from "lucide-react"
import { motion } from "framer-motion"

const SEVERITY_LABELS: Record<AlertSeverity, string> = {
  CRITICAL: "Критичные",
  HIGH: "Высокие",
  MEDIUM: "Средние",
  LOW: "Низкие",
  INFO: "Информационные"
}

const SEVERITY_COLORS: Record<AlertSeverity, string> = {
  CRITICAL: "bg-red-700",
  HIGH: "bg-orange-500",
  MEDIUM: "bg-yellow-400",
  LOW: "bg-blue-400",
  INFO: "bg-gray-400"
}

export const AlertSeverityDashboard: React.FC = () => {
  const { data, isLoading } = useAlertsData()

  const aggregated = useMemo(() => {
    const agg: Record<AlertSeverity, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0
    }

    if (!data) return agg

    for (const alert of data) {
      agg[alert.severity]++
    }

    return agg
  }, [data])

  const total = useMemo(
    () => Object.values(aggregated).reduce((a, b) => a + b, 0),
    [aggregated]
  )

  return (
    <Card title="Критичность событий" className="p-4 space-y-4" loading={isLoading}>
      <div className="flex flex-col gap-4">
        {Object.entries(aggregated).map(([severity, count]) => {
          const percent = total ? Math.round((count / total) * 100) : 0
          const severityKey = severity as AlertSeverity

          return (
            <motion.div
              key={severity}
              className="flex items-center gap-4"
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.3 }}
            >
              <Tooltip content={`${SEVERITY_LABELS[severityKey]} — ${count} (${percent}%)`}>
                <div
                  className={cn(
                    SEVERITY_COLORS[severityKey],
                    "w-4 h-4 rounded-full shrink-0"
                  )}
                />
              </Tooltip>
              <div className="flex-1">
                <div className="text-sm font-medium text-neutral-700 dark:text-neutral-300">
                  {SEVERITY_LABELS[severityKey]}
                </div>
                <ProgressBar
                  value={percent}
                  colorClass={SEVERITY_COLORS[severityKey]}
                />
              </div>
              <div className="text-sm tabular-nums text-neutral-800 dark:text-neutral-200">
                {count}
              </div>
            </motion.div>
          )
        })}
      </div>

      <div className="text-right text-xs text-neutral-500 dark:text-neutral-400">
        Всего событий: {total}
      </div>
    </Card>
  )
}
