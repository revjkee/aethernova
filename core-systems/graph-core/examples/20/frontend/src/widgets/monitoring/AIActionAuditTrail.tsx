import React, { useMemo, useState } from "react"
import { useAITraceLog } from "@/services/logs/useAITraceLog"
import { Card } from "@/shared/components/Card"
import { DataTable } from "@/shared/components/DataTable"
import { AIActionLogEntry } from "@/types/logs"
import { formatDistanceToNowStrict } from "date-fns"
import { Badge } from "@/shared/components/Badge"
import { cn } from "@/shared/utils/style"
import { IntentIcon } from "@/shared/icons/IntentIcon"
import { severityColor } from "@/shared/utils/severityColor"
import { Input } from "@/shared/components/Input"
import { motion } from "framer-motion"

const columns = [
  {
    key: "timestamp",
    header: "Время",
    render: (entry: AIActionLogEntry) => (
      <span className="text-xs text-neutral-500">
        {formatDistanceToNowStrict(new Date(entry.timestamp), { addSuffix: true })}
      </span>
    )
  },
  {
    key: "agentId",
    header: "Агент",
    render: (entry: AIActionLogEntry) => (
      <span className="font-mono text-sm">{entry.agentId}</span>
    )
  },
  {
    key: "intent",
    header: "Намерение",
    render: (entry: AIActionLogEntry) => (
      <div className="flex items-center gap-2">
        <IntentIcon intent={entry.intent} />
        <span className="capitalize">{entry.intent}</span>
      </div>
    )
  },
  {
    key: "severity",
    header: "Критичность",
    render: (entry: AIActionLogEntry) => (
      <Badge className={cn(severityColor(entry.severity))}>{entry.severity}</Badge>
    )
  },
  {
    key: "traceId",
    header: "Трейс ID",
    render: (entry: AIActionLogEntry) => (
      <span className="text-xs font-mono text-neutral-700 dark:text-neutral-300">{entry.traceId}</span>
    )
  },
  {
    key: "action",
    header: "Действие",
    render: (entry: AIActionLogEntry) => (
      <span className="text-sm text-neutral-800 dark:text-neutral-100">{entry.action}</span>
    )
  }
]

export const AIActionAuditTrail: React.FC = () => {
  const { data, isLoading } = useAITraceLog()
  const [filter, setFilter] = useState("")

  const filteredData = useMemo(() => {
    if (!data || !filter.trim()) return data
    const lower = filter.toLowerCase()
    return data.filter(
      log =>
        log.agentId.toLowerCase().includes(lower) ||
        log.intent.toLowerCase().includes(lower) ||
        log.action.toLowerCase().includes(lower) ||
        log.traceId.toLowerCase().includes(lower)
    )
  }, [data, filter])

  return (
    <Card title="Действия AI-агентов" className="p-4 space-y-4" loading={isLoading}>
      <motion.div
        initial={{ opacity: 0, y: -6 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.2 }}
      >
        <Input
          placeholder="Фильтр по агенту, действию, intent, trace ID..."
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="w-full"
        />
      </motion.div>

      <DataTable
        columns={columns}
        data={filteredData}
        striped
        rowKey="traceId"
        emptyText="Нет зафиксированных действий"
        className="text-sm"
      />
    </Card>
  )
}
