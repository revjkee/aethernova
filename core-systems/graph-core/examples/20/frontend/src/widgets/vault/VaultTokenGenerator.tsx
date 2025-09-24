import { useState } from "react"
import { generateVaultToken } from "@/services/tokenService"
import { VaultToken } from "@/types/token"
import { Spinner } from "@/shared/components/Spinner"
import { Input } from "@/shared/components/Input"
import { Select } from "@/shared/components/Select"
import { Button } from "@/shared/components/Button"
import { IconCheckCircle, IconAlertTriangle, IconKey, IconClock } from "lucide-react"
import { trackEvent } from "@/shared/utils/telemetry"
import { Badge } from "@/shared/components/Badge"
import clsx from "clsx"

interface VaultTokenGeneratorProps {
  vaultId: string
}

export const VaultTokenGenerator = ({ vaultId }: VaultTokenGeneratorProps) => {
  const [ttl, setTtl] = useState("3600")
  const [purpose, setPurpose] = useState("")
  const [scopes, setScopes] = useState<string[]>([])
  const [token, setToken] = useState<VaultToken | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const availableScopes = [
    { label: "Чтение ключей", value: "read:key" },
    { label: "Запись ключей", value: "write:key" },
    { label: "Доступ к секретам", value: "access:secret" },
    { label: "Удаление", value: "delete:key" }
  ]

  const handleGenerate = async () => {
    setLoading(true)
    setError(null)
    setToken(null)

    try {
      const res = await generateVaultToken({
        vaultId,
        ttl: parseInt(ttl, 10),
        scopes,
        purpose
      })
      setToken(res)
      trackEvent("vault_token_generated", {
        vaultId,
        ttl: res.expiresIn,
        tokenId: res.id,
        scopeCount: scopes.length
      })
    } catch (err) {
      setError("Ошибка генерации токена")
      trackEvent("vault_token_generation_error", { vaultId, error: String(err) })
    } finally {
      setLoading(false)
    }
  }

  const renderTokenResult = () => {
    if (loading) {
      return <Spinner size="md" />
    }
    if (error) {
      return (
        <div className="text-sm text-red-600 flex items-center gap-2">
          <IconAlertTriangle className="w-4 h-4" /> {error}
        </div>
      )
    }
    if (token) {
      return (
        <div className="bg-neutral-100 dark:bg-neutral-800 p-4 rounded-md mt-4 space-y-2">
          <div className="flex items-center gap-2 text-green-600">
            <IconCheckCircle className="w-5 h-5" />
            <span className="text-sm font-medium">Токен успешно сгенерирован</span>
          </div>
          <div className="text-xs text-neutral-600 dark:text-neutral-300 break-all">
            {token.token}
          </div>
          <div className="text-xs text-neutral-500 dark:text-neutral-400">
            Истекает через {token.expiresIn} секунд
          </div>
        </div>
      )
    }
    return null
  }

  return (
    <div className="border rounded-xl p-6 shadow-sm bg-white dark:bg-neutral-900 w-full max-w-xl">
      <div className="flex items-center gap-2 mb-4">
        <IconKey className="w-5 h-5 text-indigo-600" />
        <h2 className="text-sm font-semibold text-neutral-800 dark:text-neutral-100">
          Генерация временного токена доступа
        </h2>
      </div>

      <div className="space-y-4">
        <Input
          label="Назначение токена (лог)"
          placeholder="Пример: CI-пайплайн, тест агент"
          value={purpose}
          onChange={(e) => setPurpose(e.target.value)}
        />

        <Select
          label="Права доступа"
          multiple
          options={availableScopes}
          value={scopes}
          onChange={(v) => setScopes(v)}
        />

        <Input
          label="Время жизни (секунд)"
          type="number"
          icon={<IconClock className="w-4 h-4 text-neutral-400" />}
          value={ttl}
          onChange={(e) => setTtl(e.target.value)}
          min={60}
          max={86400}
        />

        <Button
          onClick={handleGenerate}
          className={clsx("w-full", loading && "opacity-60")}
          disabled={loading || !purpose || scopes.length === 0}
        >
          Сгенерировать токен
        </Button>

        {renderTokenResult()}
      </div>

      {token && (
        <div className="mt-6 text-xs text-neutral-400 dark:text-neutral-500">
          Токен не отображается повторно. Скопируйте и сохраните его безопасно.
        </div>
      )}
    </div>
  )
}
