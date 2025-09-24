import { useState, useEffect } from "react"
import { Input } from "@/shared/components/Input"
import { Select } from "@/shared/components/Select"
import { Switch } from "@/shared/components/Switch"
import { Button } from "@/shared/components/Button"
import { Spinner } from "@/shared/components/Spinner"
import { useNotification } from "@/shared/hooks/useNotification"
import { trackEvent } from "@/shared/utils/telemetry"
import {
  getRotationPolicy,
  updateRotationPolicy,
  disableRotationPolicy
} from "@/services/rotationService"
import { RotationPolicy } from "@/types/keys"
import clsx from "clsx"

interface KeyRotationSchedulerProps {
  keyId: string
  readonly?: boolean
}

const INTERVAL_OPTIONS = [
  { label: "Каждые 24 часа", value: "24h" },
  { label: "Каждые 7 дней", value: "7d" },
  { label: "Каждые 30 дней", value: "30d" },
  { label: "Каждые 90 дней", value: "90d" },
  { label: "Каждые 180 дней", value: "180d" },
]

export const KeyRotationScheduler = ({
  keyId,
  readonly = false
}: KeyRotationSchedulerProps) => {
  const [policy, setPolicy] = useState<RotationPolicy | null>(null)
  const [interval, setInterval] = useState("30d")
  const [enabled, setEnabled] = useState(false)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)

  const { notifySuccess, notifyError } = useNotification()

  useEffect(() => {
    loadPolicy()
  }, [keyId])

  const loadPolicy = async () => {
    setLoading(true)
    try {
      const result = await getRotationPolicy(keyId)
      setPolicy(result)
      setEnabled(result.enabled)
      setInterval(result.interval)
      trackEvent("rotation_policy_loaded", { keyId })
    } catch (err) {
      notifyError("Ошибка загрузки политики ротации")
      trackEvent("rotation_policy_load_error", { keyId, error: String(err) })
    } finally {
      setLoading(false)
    }
  }

  const handleSave = async () => {
    setSaving(true)
    try {
      const newPolicy: RotationPolicy = {
        keyId,
        enabled: true,
        interval,
        lastRotatedAt: policy?.lastRotatedAt ?? null
      }

      await updateRotationPolicy(keyId, newPolicy)
      setPolicy(newPolicy)
      notifySuccess("Политика ротации обновлена")
      trackEvent("rotation_policy_updated", { keyId, interval })
    } catch (err) {
      notifyError("Ошибка сохранения политики")
      trackEvent("rotation_policy_update_error", { keyId, error: String(err) })
    } finally {
      setSaving(false)
    }
  }

  const handleDisable = async () => {
    setSaving(true)
    try {
      await disableRotationPolicy(keyId)
      setEnabled(false)
      setPolicy((prev) => prev ? { ...prev, enabled: false } : null)
      notifySuccess("Автоматическая ротация отключена")
      trackEvent("rotation_policy_disabled", { keyId })
    } catch (err) {
      notifyError("Ошибка при отключении политики")
      trackEvent("rotation_policy_disable_error", { keyId, error: String(err) })
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="space-y-6">
      <div className="text-lg font-semibold text-neutral-800 dark:text-neutral-100">
        Планировщик ротации ключа
      </div>

      {loading ? (
        <div className="flex justify-center py-6"><Spinner size="lg" /></div>
      ) : (
        <div className="space-y-5">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-neutral-700 dark:text-neutral-300">
              Автоматическая ротация включена
            </span>
            <Switch
              checked={enabled}
              disabled={readonly || saving}
              onCheckedChange={(v) => setEnabled(v)}
            />
          </div>

          {enabled && (
            <div className="space-y-3">
              <label className="text-sm font-semibold text-neutral-700 dark:text-neutral-300">
                Интервал ротации
              </label>
              <Select
                options={INTERVAL_OPTIONS}
                value={interval}
                onChange={setInterval}
                disabled={readonly}
              />
            </div>
          )}

          {!readonly && (
            <div className="flex justify-end gap-4 pt-4">
              {enabled ? (
                <>
                  <Button
                    variant="outline"
                    onClick={handleDisable}
                    disabled={saving}
                  >
                    Отключить
                  </Button>
                  <Button
                    variant="primary"
                    onClick={handleSave}
                    disabled={saving}
                    className={clsx("min-w-[160px]", saving && "opacity-60")}
                  >
                    {saving ? <Spinner size="sm" /> : "Сохранить"}
                  </Button>
                </>
              ) : (
                <Button
                  variant="primary"
                  onClick={handleSave}
                  disabled={saving}
                  className={clsx("min-w-[180px]", saving && "opacity-60")}
                >
                  {saving ? <Spinner size="sm" /> : "Включить ротацию"}
                </Button>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
