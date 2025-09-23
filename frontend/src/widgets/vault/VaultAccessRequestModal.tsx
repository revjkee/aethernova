import { useState, useEffect } from "react"
import { Modal } from "@/shared/components/Modal"
import { Input } from "@/shared/components/Input"
import { Textarea } from "@/shared/components/Textarea"
import { Select } from "@/shared/components/Select"
import { Button } from "@/shared/components/Button"
import { Spinner } from "@/shared/components/Spinner"
import { useNotification } from "@/shared/hooks/useNotification"
import { sendVaultAccessRequest } from "@/services/accessService"
import { trackEvent } from "@/shared/utils/telemetry"
import clsx from "clsx"

interface VaultAccessRequestModalProps {
  isOpen: boolean
  onClose: () => void
  vaultId: string
  requesterEmail?: string
}

const DURATION_OPTIONS = [
  { label: "15 минут", value: "15m" },
  { label: "1 час", value: "1h" },
  { label: "3 часа", value: "3h" },
  { label: "24 часа", value: "24h" },
  { label: "До отзыва", value: "indefinite" },
]

export const VaultAccessRequestModal = ({
  isOpen,
  onClose,
  vaultId,
  requesterEmail,
}: VaultAccessRequestModalProps) => {
  const [purpose, setPurpose] = useState("")
  const [duration, setDuration] = useState("1h")
  const [additionalNotes, setAdditionalNotes] = useState("")
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")

  const { notifySuccess, notifyError } = useNotification()

  useEffect(() => {
    if (!isOpen) reset()
  }, [isOpen])

  const reset = () => {
    setPurpose("")
    setDuration("1h")
    setAdditionalNotes("")
    setLoading(false)
    setError("")
  }

  const handleSubmit = async () => {
    if (!purpose.trim()) {
      setError("Необходимо указать цель запроса.")
      return
    }

    setLoading(true)
    try {
      await sendVaultAccessRequest({
        vaultId,
        email: requesterEmail,
        reason: purpose.trim(),
        duration,
        notes: additionalNotes.trim(),
      })

      trackEvent("vault_access_requested", {
        vaultId,
        duration,
        requester: requesterEmail,
      })

      notifySuccess("Запрос доступа отправлен на рассмотрение")
      onClose()
    } catch (err) {
      notifyError("Ошибка при отправке запроса")
      trackEvent("vault_access_request_error", {
        vaultId,
        error: String(err),
      })
    } finally {
      setLoading(false)
    }
  }

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Запрос доступа к секрету"
      size="md"
    >
      <div className="space-y-6 px-1 sm:px-3">
        <div className="space-y-2">
          <label className="text-sm font-semibold text-neutral-800 dark:text-neutral-200">
            Цель запроса
          </label>
          <Textarea
            value={purpose}
            onChange={(e) => setPurpose(e.target.value)}
            placeholder="Укажите причину, например: временный анализ, отладка, аудит"
            rows={3}
          />
          {error && <div className="text-sm text-red-600">{error}</div>}
        </div>

        <div className="space-y-2">
          <label className="text-sm font-semibold text-neutral-800 dark:text-neutral-200">
            Желаемая длительность доступа
          </label>
          <Select
            options={DURATION_OPTIONS}
            value={duration}
            onChange={setDuration}
          />
        </div>

        <div className="space-y-2">
          <label className="text-sm font-semibold text-neutral-800 dark:text-neutral-200">
            Дополнительные примечания (необязательно)
          </label>
          <Textarea
            value={additionalNotes}
            onChange={(e) => setAdditionalNotes(e.target.value)}
            placeholder="Контекст, временной интервал, ссылки на задачу или инцидент"
            rows={2}
          />
        </div>

        <div className="flex justify-end pt-3 gap-4">
          <Button variant="outline" onClick={onClose} disabled={loading}>
            Отмена
          </Button>
          <Button
            variant="primary"
            onClick={handleSubmit}
            disabled={loading || !purpose.trim()}
            className={clsx("min-w-[160px]", loading && "opacity-60")}
          >
            {loading ? <Spinner size="sm" /> : "Отправить запрос"}
          </Button>
        </div>
      </div>
    </Modal>
  )
}
