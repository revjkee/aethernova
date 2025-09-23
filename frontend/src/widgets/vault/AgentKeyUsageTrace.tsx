import { useEffect, useState } from "react"
import { getKeyUsageTrace } from "@/services/traceService"
import { AgentUsageRecord } from "@/types/audit"
import { Spinner } from "@/shared/components/Spinner"
import { Table } from "@/shared/components/Table"
import { Badge } from "@/shared/components/Badge"
import { IconShieldCheck, IconEye, IconAlertTriangle, IconCpu, IconRefreshCw } from "lucide-react"
import { formatDistanceToNowStrict } from "date-fns"
import { trackEvent } from "@/shared/utils/telemetry"

interface AgentKeyUsageTraceProps {
  keyId: string
}

export const AgentKeyUsageTrace = ({ keyId }: AgentKeyUsageTraceProps) => {
  const [records, setRecords] = useState<AgentUsageRecord[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetchUsage()
  }, [keyId])

  const fetchUsage = async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await getKeyUsageTrace(keyId)
      setRecords(data)
      trackEvent("agent_key_usage_trace_loaded", { keyId, count: data.length })
    } catch (err) {
      setError("Не удалось загрузить следы использования ключа")
      trackEvent("agent_key_usage_trace_error", { keyId, error: String(err) })
    } finally {
      setLoading(false)
    }
  }

  const renderStatusBadge = (status: string) => {
    switch (status) {
      case "success":
        return <Badge color="green">успешно</Badge>
      case "denied":
        return <Badge color="red">отказано</Badge>
      case "timeout":
        return <Badge color="yellow">таймаут</Badge>
      default:
        return <Badge color="gray">неизвестно</Badge>
    }
  }

  return (
    <div className="w-full border rounded-xl bg-white dark:bg-neutral-900 shadow-sm p-4">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <IconCpu className="w-5 h-5 text-violet-600" />
          <span className="text-sm font-semibold text-neutral-800 dark:text-white">
            Следы использования ключа AI-агентами
          </span>
        </div>
        <button
          onClick={fetchUsage}
          className="flex items-center gap-1 text-xs text-neutral-500 hover:text-neutral-900 dark:hover:text-white"
        >
          <IconRefreshCw className="w-4 h-4" />
          Обновить
        </button>
      </div>

      {loading ? (
        <div className="flex justify-center items-center h-32">
          <Spinner size="md" />
        </div>
      ) : error ? (
        <div className="text-sm text-red-600 flex items-center gap-2">
          <IconAlertTriangle className="w-4 h-4" /> {error}
        </div>
      ) : (
        <Table
          columns={[
            { label: "Агент", key: "agentId" },
            { label: "Действие", key: "action" },
            { label: "IP / Host", key: "origin" },
            { label: "Цель", key: "target" },
            { label: "Результат", key: "status", render: (row) => renderStatusBadge(row.status) },
            { label: "Время", key: "timestamp", render: (row) => formatDistanceToNowStrict(new Date(row.timestamp), { addSuffix: true }) }
          ]}
          data={records}
          rowKey="traceId"
          className="text-xs"
        />
      )}
    </div>
  )
}
