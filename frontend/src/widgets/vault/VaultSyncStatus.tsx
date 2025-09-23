import { useEffect, useState } from "react"
import { getVaultSyncState } from "@/services/syncService"
import { VaultSyncState } from "@/types/sync"
import { Tooltip } from "@/shared/components/Tooltip"
import { Spinner } from "@/shared/components/Spinner"
import { IconCloud, IconAlertTriangle, IconRefresh, IconCheck, IconLoader, IconXCircle } from "lucide-react"
import clsx from "clsx"
import { trackEvent } from "@/shared/utils/telemetry"

interface VaultSyncStatusProps {
  vaultId: string
  pollingIntervalMs?: number
  minimal?: boolean
}

export const VaultSyncStatus = ({
  vaultId,
  pollingIntervalMs = 8000,
  minimal = false
}: VaultSyncStatusProps) => {
  const [syncState, setSyncState] = useState<VaultSyncState | null>(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    let interval: NodeJS.Timeout

    const fetchSync = async () => {
      setLoading(true)
      try {
        const state = await getVaultSyncState(vaultId)
        setSyncState(state)
        trackEvent("vault_sync_status_fetched", { vaultId, status: state.status })
      } catch (err) {
        setSyncState({ status: "error", lastSynced: null, reason: String(err) })
        trackEvent("vault_sync_status_error", { vaultId, error: String(err) })
      } finally {
        setLoading(false)
      }
    }

    fetchSync()
    interval = setInterval(fetchSync, pollingIntervalMs)

    return () => clearInterval(interval)
  }, [vaultId, pollingIntervalMs])

  const getStatusConfig = (state: VaultSyncState | null) => {
    if (!state) return { label: "Неизвестно", color: "gray", icon: IconCloud }

    switch (state.status) {
      case "synced":
        return { label: "Синхронизировано", color: "green", icon: IconCheck }
      case "pending":
        return { label: "Синхронизация...", color: "blue", icon: IconLoader }
      case "error":
        return { label: "Ошибка", color: "red", icon: IconXCircle }
      case "desynced":
        return { label: "Несоответствие", color: "yellow", icon: IconAlertTriangle }
      case "conflict":
        return { label: "Конфликт", color: "orange", icon: IconRefresh }
      case "recovery":
        return { label: "Восстановление", color: "purple", icon: IconLoader }
      default:
        return { label: "Неизвестно", color: "gray", icon: IconCloud }
    }
  }

  const status = getStatusConfig(syncState)
  const Icon = status.icon

  return (
    <div className="flex items-center space-x-2">
      <Tooltip
        content={
          <div className="text-sm">
            <div className="font-medium">{status.label}</div>
            {syncState?.lastSynced && (
              <div className="text-xs text-neutral-400">
                Последняя синхронизация: {new Date(syncState.lastSynced).toLocaleString()}
              </div>
            )}
            {syncState?.reason && (
              <div className="text-xs text-red-500 mt-1">{syncState.reason}</div>
            )}
          </div>
        }
      >
        <div
          className={clsx(
            "rounded-full p-1.5 flex items-center justify-center",
            {
              "bg-green-100 text-green-700": status.color === "green",
              "bg-blue-100 text-blue-700": status.color === "blue",
              "bg-yellow-100 text-yellow-800": status.color === "yellow",
              "bg-orange-100 text-orange-800": status.color === "orange",
              "bg-purple-100 text-purple-800": status.color === "purple",
              "bg-red-100 text-red-700": status.color === "red",
              "bg-gray-100 text-gray-600": status.color === "gray",
            },
            minimal && "p-1"
          )}
        >
          {loading ? <Spinner size="xs" /> : <Icon size={minimal ? 14 : 18} />}
        </div>
      </Tooltip>

      {!minimal && (
        <span
          className={clsx("text-sm font-medium", {
            "text-green-700": status.color === "green",
            "text-blue-700": status.color === "blue",
            "text-yellow-800": status.color === "yellow",
            "text-orange-800": status.color === "orange",
            "text-purple-800": status.color === "purple",
            "text-red-700": status.color === "red",
            "text-gray-600": status.color === "gray",
          })}
        >
          {status.label}
        </span>
      )}
    </div>
  )
}
