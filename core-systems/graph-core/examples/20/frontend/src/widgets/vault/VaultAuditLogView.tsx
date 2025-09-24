import { useEffect, useState } from "react"
import { getVaultAuditLog } from "@/services/auditService"
import { AuditLogEntry } from "@/types/audit"
import { Table } from "@/shared/components/Table"
import { Spinner } from "@/shared/components/Spinner"
import { formatDateTime } from "@/shared/utils/date"
import { Select } from "@/shared/components/Select"
import { Input } from "@/shared/components/Input"
import { trackEvent } from "@/shared/utils/telemetry"
import { useDebounce } from "@/shared/hooks/useDebounce"
import clsx from "clsx"

const ACTIONS = [
  { label: "Все действия", value: "" },
  { label: "Создание", value: "create" },
  { label: "Чтение", value: "read" },
  { label: "Обновление", value: "update" },
  { label: "Удаление", value: "delete" },
  { label: "Откат", value: "rollback" },
]

export const VaultAuditLogView = () => {
  const [logs, setLogs] = useState<AuditLogEntry[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")
  const [actionFilter, setActionFilter] = useState("")
  const [userSearch, setUserSearch] = useState("")
  const [debouncedUserSearch] = useDebounce(userSearch, 400)

  useEffect(() => {
    fetchLogs()
    const interval = setInterval(fetchLogs, 30000) // обновление каждые 30 сек
    return () => clearInterval(interval)
  }, [actionFilter, debouncedUserSearch])

  const fetchLogs = async () => {
    setLoading(true)
    try {
      const result = await getVaultAuditLog({
        action: actionFilter,
        user: debouncedUserSearch
      })
      setLogs(result)
      trackEvent("vault_audit_loaded", {
        actionFilter,
        userSearch: debouncedUserSearch,
        count: result.length
      })
    } catch (err) {
      setError("Ошибка загрузки журнала аудита")
      trackEvent("vault_audit_error", {
        error: String(err)
      })
    } finally {
      setLoading(false)
    }
  }

  const columns = [
    {
      header: "Дата и время",
      accessor: (entry: AuditLogEntry) => formatDateTime(entry.timestamp),
    },
    {
      header: "Действие",
      accessor: (entry: AuditLogEntry) => renderActionLabel(entry.action),
    },
    {
      header: "Пользователь / Агент",
      accessor: (entry: AuditLogEntry) => entry.actor || "—",
    },
    {
      header: "Объект",
      accessor: (entry: AuditLogEntry) => entry.objectName || entry.objectId,
    },
    {
      header: "IP / Agent-ID",
      accessor: (entry: AuditLogEntry) => entry.origin || "—",
    },
    {
      header: "Комментарий",
      accessor: (entry: AuditLogEntry) => entry.comment || "—",
    },
  ]

  const renderActionLabel = (action: string) => {
    switch (action) {
      case "create":
        return "Создание"
      case "read":
        return "Чтение"
      case "update":
        return "Обновление"
      case "delete":
        return "Удаление"
      case "rollback":
        return "Откат"
      default:
        return "—"
    }
  }

  return (
    <div className="p-4 space-y-4">
      <div className="flex flex-col md:flex-row md:items-end md:justify-between gap-4">
        <div className="flex gap-4">
          <Select
            label="Фильтр действия"
            options={ACTIONS}
            value={actionFilter}
            onChange={setActionFilter}
            className="min-w-[200px]"
          />
          <Input
            label="Поиск по пользователю/агенту"
            value={userSearch}
            onChange={(e) => setUserSearch(e.target.value)}
            placeholder="Например: admin@neuro.city"
          />
        </div>
        {loading && <Spinner size="sm" />}
      </div>

      {error ? (
        <div className="text-red-600 text-sm">{error}</div>
      ) : (
        <Table
          data={logs}
          columns={columns}
          emptyMessage="Нет записей аудита по заданным параметрам"
        />
      )}
    </div>
  )
}
