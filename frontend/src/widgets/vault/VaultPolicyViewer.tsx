import { useEffect, useState } from "react"
import { getVaultPolicies } from "@/services/policyService"
import { VaultPolicy } from "@/types/policy"
import { Spinner } from "@/shared/components/Spinner"
import { Badge } from "@/shared/components/Badge"
import { IconShieldCheck, IconShieldOff, IconUsers, IconUser, IconInfo } from "lucide-react"
import { Tooltip } from "@/shared/components/Tooltip"
import { trackEvent } from "@/shared/utils/telemetry"
import clsx from "clsx"

interface VaultPolicyViewerProps {
  vaultId: string
}

export const VaultPolicyViewer = ({ vaultId }: VaultPolicyViewerProps) => {
  const [policies, setPolicies] = useState<VaultPolicy[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetchPolicies()
  }, [vaultId])

  const fetchPolicies = async () => {
    setLoading(true)
    try {
      const response = await getVaultPolicies(vaultId)
      setPolicies(response)
      trackEvent("vault_policy_loaded", { vaultId, count: response.length })
    } catch (err) {
      setError("Ошибка загрузки политик")
      trackEvent("vault_policy_load_error", { vaultId, error: String(err) })
    } finally {
      setLoading(false)
    }
  }

  const renderPolicyTypeIcon = (type: string) => {
    switch (type) {
      case "user":
        return <IconUser className="w-4 h-4 text-blue-600" />
      case "group":
        return <IconUsers className="w-4 h-4 text-indigo-600" />
      case "system":
        return <IconInfo className="w-4 h-4 text-neutral-500" />
      default:
        return <IconInfo className="w-4 h-4 text-gray-500" />
    }
  }

  return (
    <div className="space-y-6">
      <div className="text-lg font-semibold text-neutral-800 dark:text-neutral-100">
        Политики доступа
      </div>

      {loading ? (
        <div className="flex justify-center py-10"><Spinner size="lg" /></div>
      ) : error ? (
        <div className="text-sm text-red-600">{error}</div>
      ) : policies.length === 0 ? (
        <div className="text-sm text-neutral-500">Нет назначенных политик.</div>
      ) : (
        <div className="space-y-4">
          {policies.map((policy) => (
            <div
              key={policy.id}
              className={clsx(
                "border rounded-lg p-4 shadow-sm space-y-2",
                policy.active ? "bg-white dark:bg-neutral-900" : "bg-neutral-100 dark:bg-neutral-800"
              )}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  {renderPolicyTypeIcon(policy.subjectType)}
                  <div className="text-sm font-medium text-neutral-800 dark:text-neutral-200">
                    {policy.subjectLabel}
                  </div>
                </div>
                <div>
                  {policy.active ? (
                    <Badge variant="success" icon={<IconShieldCheck className="w-3 h-3" />}>
                      Активна
                    </Badge>
                  ) : (
                    <Badge variant="danger" icon={<IconShieldOff className="w-3 h-3" />}>
                      Отключена
                    </Badge>
                  )}
                </div>
              </div>

              <div className="text-xs text-neutral-500 dark:text-neutral-400">
                Роль: <span className="font-medium text-neutral-700 dark:text-neutral-300">{policy.role}</span>
              </div>

              {policy.conditions?.length > 0 && (
                <div className="text-xs text-neutral-400 dark:text-neutral-500">
                  Условия: {policy.conditions.map(c => `${c.field}=${c.value}`).join(", ")}
                </div>
              )}

              {policy.source && (
                <Tooltip content={`Источник: ${policy.source}`}>
                  <div className="text-xs text-neutral-400 dark:text-neutral-500">
                    Источник: <span className="underline cursor-help">{policy.sourceLabel}</span>
                  </div>
                </Tooltip>
              )}

              {policy.priority != null && (
                <div className="text-xs text-neutral-400 dark:text-neutral-500">
                  Приоритет: {policy.priority}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
