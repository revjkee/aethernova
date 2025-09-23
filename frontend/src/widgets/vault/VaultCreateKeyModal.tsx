import { useState, useRef, useEffect } from "react"
import { Modal } from "@/shared/components/Modal"
import { Input } from "@/shared/components/Input"
import { Button } from "@/shared/components/Button"
import { useNotification } from "@/shared/hooks/useNotification"
import { validateKeyName, validateMetadata } from "@/shared/utils/validators"
import { Spinner } from "@/shared/components/Spinner"
import { useVaultStore } from "@/state/vault"
import { trackEvent } from "@/shared/utils/telemetry"
import { generateKeySecurely } from "@/shared/utils/crypto"
import { nanoid } from "nanoid"
import clsx from "clsx"

interface VaultCreateKeyModalProps {
  isOpen: boolean
  onClose: () => void
}

export const VaultCreateKeyModal = ({ isOpen, onClose }: VaultCreateKeyModalProps) => {
  const { addKey } = useVaultStore()
  const { notifySuccess, notifyError } = useNotification()

  const [keyName, setKeyName] = useState("")
  const [metadata, setMetadata] = useState("")
  const [errorKeyName, setErrorKeyName] = useState("")
  const [errorMetadata, setErrorMetadata] = useState("")
  const [loading, setLoading] = useState(false)
  const [generatedKey, setGeneratedKey] = useState("")
  const [copySuccess, setCopySuccess] = useState(false)

  const keyRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (!isOpen) {
      resetState()
    }
  }, [isOpen])

  const resetState = () => {
    setKeyName("")
    setMetadata("")
    setErrorKeyName("")
    setErrorMetadata("")
    setGeneratedKey("")
    setCopySuccess(false)
    setLoading(false)
  }

  const handleGenerate = async () => {
    setErrorKeyName("")
    setErrorMetadata("")

    const keyNameError = validateKeyName(keyName)
    const metadataError = validateMetadata(metadata)

    if (keyNameError || metadataError) {
      setErrorKeyName(keyNameError || "")
      setErrorMetadata(metadataError || "")
      return
    }

    setLoading(true)

    try {
      const key = await generateKeySecurely()
      const id = nanoid(16)

      await addKey({
        id,
        name: keyName,
        metadata,
        secret: key,
        createdAt: new Date().toISOString()
      })

      setGeneratedKey(key)
      trackEvent("vault_key_created", { keyName, metadata })
      notifySuccess("Ключ успешно создан")
    } catch (err) {
      notifyError("Ошибка при генерации ключа")
      trackEvent("vault_key_create_error", { error: String(err) })
    } finally {
      setLoading(false)
    }
  }

  const handleCopy = () => {
    if (!generatedKey) return
    navigator.clipboard.writeText(generatedKey)
    setCopySuccess(true)
    setTimeout(() => setCopySuccess(false), 2000)
  }

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Создание нового ключа" size="lg">
      <div className="space-y-6 px-1 sm:px-3">
        {!generatedKey ? (
          <>
            <div className="space-y-2">
              <label className="text-sm font-semibold text-neutral-700 dark:text-neutral-200">Название ключа</label>
              <Input
                value={keyName}
                onChange={e => setKeyName(e.target.value)}
                placeholder="Уникальное имя ключа"
                error={!!errorKeyName}
              />
              {errorKeyName && <p className="text-red-500 text-xs">{errorKeyName}</p>}
            </div>

            <div className="space-y-2">
              <label className="text-sm font-semibold text-neutral-700 dark:text-neutral-200">Метаданные</label>
              <Input
                value={metadata}
                onChange={e => setMetadata(e.target.value)}
                placeholder="Описание, категории, связи и т.д."
                error={!!errorMetadata}
              />
              {errorMetadata && <p className="text-red-500 text-xs">{errorMetadata}</p>}
            </div>

            <div className="flex justify-end">
              <Button onClick={handleGenerate} disabled={loading} variant="primary" className="min-w-[160px]">
                {loading ? <Spinner size="sm" /> : "Сгенерировать ключ"}
              </Button>
            </div>
          </>
        ) : (
          <div className="space-y-4">
            <div className="text-green-600 font-semibold">Ключ успешно сгенерирован:</div>
            <div className="relative">
              <input
                ref={keyRef}
                value={generatedKey}
                readOnly
                className="w-full px-4 py-2 font-mono text-sm border border-neutral-300 dark:border-neutral-700 rounded-md bg-neutral-100 dark:bg-neutral-800 text-neutral-800 dark:text-white"
              />
              <button
                onClick={handleCopy}
                className="absolute right-2 top-2 text-sm text-blue-500 hover:text-blue-700"
              >
                {copySuccess ? "Скопировано" : "Копировать"}
              </button>
            </div>
            <div className="text-xs text-neutral-600 dark:text-neutral-400">
              Внимание: сохраните ключ. Он будет показан только один раз.
            </div>
            <div className="flex justify-end gap-3">
              <Button variant="outline" onClick={onClose}>
                Закрыть
              </Button>
            </div>
          </div>
        )}
      </div>
    </Modal>
  )
}
