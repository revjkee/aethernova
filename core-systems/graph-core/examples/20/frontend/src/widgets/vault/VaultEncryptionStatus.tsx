import { useEffect, useState } from "react"
import { ShieldCheckIcon, ShieldExclamationIcon, LoaderIcon, LockIcon } from "@/shared/assets/icons"
import { Tooltip } from "@/shared/components/Tooltip"
import { useEncryptionStatusStore } from "@/state/encryptionStatus"
import { getVaultEncryptionStatus } from "@/services/vaultService"
import { trackEvent } from "@/shared/utils/telemetry"
import clsx from "clsx"

interface VaultEncryptionStatusProps {
  vaultId: string
  className?: string
}

type StatusLevel = "encrypted" | "partial" | "unencrypted" | "loading" | "error"

export const VaultEncryptionStatus = ({ vaultId, className }: VaultEncryptionStatusProps) => {
  const [status, setStatus] = useState<StatusLevel>("loading")
  const [details, setDetails] = useState("")
  const { updateStatus } = useEncryptionStatusStore()

  useEffect(() => {
    fetchStatus()
    const interval = setInterval(fetchStatus, 15000) // автообновление каждые 15 сек
    return () => clearInterval(interval)
  }, [vaultId])

  const fetchStatus = async () => {
    setStatus("loading")
    try {
      const result = await getVaultEncryptionStatus(vaultId)
      setStatus(result.level)
      setDetails(result.description)
      updateStatus(vaultId, result.level)
      trackEvent("vault_encryption_status_checked", {
        vaultId,
        level: result.level
      })
    } catch (error) {
      setStatus("error")
      setDetails("Ошибка при проверке статуса")
      trackEvent("vault_encryption_status_error", {
        vaultId,
        error: String(error)
      })
    }
  }

  const getStatusIcon = () => {
    switch (status) {
      case "encrypted":
        return (
          <Tooltip content="Все данные зашифрованы.">
            <ShieldCheckIcon className="text-green-600 w-5 h-5" />
          </Tooltip>
        )
      case "partial":
        return (
          <Tooltip content="Часть данных не зашифрована или устарела.">
            <ShieldExclamationIcon className="text-yellow-500 w-5 h-5" />
          </Tooltip>
        )
      case "unencrypted":
        return (
          <Tooltip content="Данные не зашифрованы. Рекомендуется немедленно зашифровать.">
            <LockIcon className="text-red-600 w-5 h-5" />
          </Tooltip>
        )
      case "loading":
        return (
          <Tooltip content="Проверка статуса шифрования...">
            <LoaderIcon className="text-blue-500 w-5 h-5 animate-spin" />
          </Tooltip>
        )
      case "error":
        return (
          <Tooltip content="Ошибка получения статуса.">
            <ShieldExclamationIcon className="text-neutral-500 w-5 h-5" />
          </Tooltip>
        )
      default:
        return null
    }
  }

  const getLabel = () => {
    switch (status) {
      case "encrypted":
        return "Зашифровано"
      case "partial":
        return "Частично"
      case "unencrypted":
        return "Не зашифровано"
      case "loading":
        return "Проверка..."
      case "error":
        return "Ошибка"
      default:
        return "-"
    }
  }

  return (
    <div className={clsx("inline-flex items-center gap-2", className)}>
      {getStatusIcon()}
      <span
        className={clsx("text-sm font-medium", {
          "text-green-700": status === "encrypted",
          "text-yellow-700": status === "partial",
          "text-red-700": status === "unencrypted",
          "text-blue-600": status === "loading",
          "text-neutral-500": status === "error"
        })}
      >
        {getLabel()}
      </span>
    </div>
  )
}
