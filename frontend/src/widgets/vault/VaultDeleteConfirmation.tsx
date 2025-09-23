import { useEffect, useRef, useState } from "react"
import { Modal } from "@/shared/components/Modal"
import { Input } from "@/shared/components/Input"
import { Button } from "@/shared/components/Button"
import { Spinner } from "@/shared/components/Spinner"
import { useNotification } from "@/shared/hooks/useNotification"
import { trackEvent } from "@/shared/utils/telemetry"
import clsx from "clsx"

interface VaultDeleteConfirmationProps {
  isOpen: boolean
  onClose: () => void
  itemName: string
  itemId: string
  onConfirm: (itemId: string) => Promise<void>
}

export const VaultDeleteConfirmation = ({
  isOpen,
  onClose,
  itemName,
  itemId,
  onConfirm
}: VaultDeleteConfirmationProps) => {
  const [input, setInput] = useState("")
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")
  const inputRef = useRef<HTMLInputElement>(null)
  const { notifySuccess, notifyError } = useNotification()

  const confirmationPhrase = `удалить ${itemName}`

  useEffect(() => {
    if (isOpen) {
      setTimeout(() => {
        inputRef.current?.focus()
      }, 100)
    }
  }, [isOpen])

  useEffect(() => {
    if (!isOpen) resetState()
  }, [isOpen])

  const resetState = () => {
    setInput("")
    setLoading(false)
    setError("")
  }

  const handleDelete = async () => {
    setError("")
    if (input.trim() !== confirmationPhrase) {
      setError("Фраза подтверждения введена неверно.")
      return
    }

    setLoading(true)

    try {
      await onConfirm(itemId)
      trackEvent("vault_item_deleted", { itemId, itemName })
      notifySuccess("Ключ успешно удалён")
      onClose()
    } catch (err) {
      notifyError("Ошибка при удалении ключа")
      trackEvent("vault_delete_error", { itemId, error: String(err) })
    } finally {
      setLoading(false)
    }
  }

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Подтверждение удаления"
      size="md"
    >
      <div className="space-y-5 px-1 sm:px-3">
        <p className="text-neutral-700 dark:text-neutral-200">
          Вы уверены, что хотите <span className="text-red-600 font-semibold">безвозвратно удалить</span> ключ <span className="font-semibold">"{itemName}"</span>?
        </p>
        <p className="text-sm text-neutral-500 dark:text-neutral-400">
          Для подтверждения введите фразу <span className="font-mono bg-neutral-100 dark:bg-neutral-800 px-2 py-1 rounded">удалить {itemName}</span>
        </p>

        <Input
          ref={inputRef}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder={`Введите: удалить ${itemName}`}
          error={!!error}
        />
        {error && <div className="text-sm text-red-500">{error}</div>}

        <div className="flex justify-end gap-3 pt-2">
          <Button variant="outline" onClick={onClose} disabled={loading}>
            Отмена
          </Button>
          <Button
            variant="danger"
            onClick={handleDelete}
            disabled={loading || input.trim() !== confirmationPhrase}
            className={clsx("min-w-[140px]", loading && "opacity-70")}
          >
            {loading ? <Spinner size="sm" /> : "Удалить"}
          </Button>
        </div>
      </div>
    </Modal>
  )
}
