import { useEffect, useState } from "react"
import {
  getGPGKeys,
  importGPGKey,
  deleteGPGKey,
  validateGPGKey,
  exportGPGKey,
} from "@/services/gpgService"
import { GPGKey } from "@/types/gpg"
import { Input } from "@/shared/components/Input"
import { Textarea } from "@/shared/components/Textarea"
import { Button } from "@/shared/components/Button"
import { Spinner } from "@/shared/components/Spinner"
import { trackEvent } from "@/shared/utils/telemetry"
import { useNotification } from "@/shared/hooks/useNotification"
import { ConfirmModal } from "@/shared/components/ConfirmModal"
import { Tooltip } from "@/shared/components/Tooltip"
import clsx from "clsx"

export const GPGSignatureManager = () => {
  const [keys, setKeys] = useState<GPGKey[]>([])
  const [loading, setLoading] = useState(false)
  const [importText, setImportText] = useState("")
  const [deletingKeyId, setDeletingKeyId] = useState<string | null>(null)
  const [validatingKeyId, setValidatingKeyId] = useState<string | null>(null)
  const [exportingKeyId, setExportingKeyId] = useState<string | null>(null)

  const { notifySuccess, notifyError } = useNotification()

  useEffect(() => {
    fetchKeys()
  }, [])

  const fetchKeys = async () => {
    setLoading(true)
    try {
      const result = await getGPGKeys()
      setKeys(result)
      trackEvent("gpg_keys_loaded", { count: result.length })
    } catch (err) {
      notifyError("Ошибка загрузки GPG-ключей")
      trackEvent("gpg_keys_error", { error: String(err) })
    } finally {
      setLoading(false)
    }
  }

  const handleImport = async () => {
    if (!importText.trim()) return
    setLoading(true)
    try {
      await importGPGKey(importText.trim())
      notifySuccess("Ключ успешно импортирован")
      trackEvent("gpg_key_imported", {})
      setImportText("")
      await fetchKeys()
    } catch (err) {
      notifyError("Ошибка при импорте ключа")
      trackEvent("gpg_key_import_error", { error: String(err) })
    } finally {
      setLoading(false)
    }
  }

  const handleDelete = async (id: string) => {
    setDeletingKeyId(id)
    try {
      await deleteGPGKey(id)
      notifySuccess("Ключ удалён")
      trackEvent("gpg_key_deleted", { id })
      await fetchKeys()
    } catch (err) {
      notifyError("Ошибка удаления ключа")
      trackEvent("gpg_key_delete_error", { id, error: String(err) })
    } finally {
      setDeletingKeyId(null)
    }
  }

  const handleValidate = async (id: string) => {
    setValidatingKeyId(id)
    try {
      const result = await validateGPGKey(id)
      notifySuccess(result.valid ? "Ключ действителен" : "Ключ недействителен")
      trackEvent("gpg_key_validated", { id, valid: result.valid })
    } catch (err) {
      notifyError("Ошибка проверки подписи")
      trackEvent("gpg_key_validation_error", { id, error: String(err) })
    } finally {
      setValidatingKeyId(null)
    }
  }

  const handleExport = async (id: string) => {
    setExportingKeyId(id)
    try {
      const blob = await exportGPGKey(id)
      const url = URL.createObjectURL(blob)
      const link = document.createElement("a")
      link.href = url
      link.download = `gpg_key_${id}.asc`
      document.body.appendChild(link)
      link.click()
      link.remove()
      URL.revokeObjectURL(url)
      trackEvent("gpg_key_exported", { id })
    } catch (err) {
      notifyError("Ошибка экспорта ключа")
      trackEvent("gpg_key_export_error", { id, error: String(err) })
    } finally {
      setExportingKeyId(null)
    }
  }

  return (
    <div className="space-y-6">
      <div className="text-xl font-semibold text-neutral-800 dark:text-neutral-100">
        Управление GPG-подписями
      </div>

      <div className="space-y-2">
        <Textarea
          label="Импорт публичного ключа"
          value={importText}
          onChange={(e) => setImportText(e.target.value)}
          placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----"
        />
        <Button
          variant="primary"
          onClick={handleImport}
          disabled={!importText.trim() || loading}
        >
          {loading ? <Spinner size="sm" /> : "Импортировать"}
        </Button>
      </div>

      <div className="pt-4 border-t space-y-3">
        <div className="text-lg font-medium text-neutral-700 dark:text-neutral-200">
          Импортированные ключи
        </div>
        {loading ? (
          <div className="flex justify-center py-4"><Spinner size="lg" /></div>
        ) : keys.length === 0 ? (
          <div className="text-neutral-500 text-sm">Нет загруженных ключей</div>
        ) : (
          <ul className="space-y-2">
            {keys.map((key) => (
              <li
                key={key.id}
                className="flex justify-between items-center border px-4 py-2 rounded-md bg-neutral-50 dark:bg-neutral-900"
              >
                <div className="space-y-0.5">
                  <div className="text-sm font-medium text-neutral-800 dark:text-neutral-100">
                    {key.email || "Без email"}
                  </div>
                  <div className="text-xs text-neutral-500 dark:text-neutral-400">
                    Fingerprint: {key.fingerprint}
                  </div>
                </div>
                <div className="flex gap-2">
                  <Tooltip content="Проверить подпись">
                    <Button
                      size="xs"
                      onClick={() => handleValidate(key.id)}
                      disabled={validatingKeyId === key.id}
                    >
                      {validatingKeyId === key.id ? <Spinner size="xs" /> : "Проверить"}
                    </Button>
                  </Tooltip>
                  <Tooltip content="Экспортировать ключ">
                    <Button
                      size="xs"
                      onClick={() => handleExport(key.id)}
                      disabled={exportingKeyId === key.id}
                    >
                      {exportingKeyId === key.id ? <Spinner size="xs" /> : "Экспорт"}
                    </Button>
                  </Tooltip>
                  <Tooltip content="Удалить ключ">
                    <Button
                      variant="danger"
                      size="xs"
                      onClick={() => handleDelete(key.id)}
                      disabled={deletingKeyId === key.id}
                    >
                      {deletingKeyId === key.id ? <Spinner size="xs" /> : "Удалить"}
                    </Button>
                  </Tooltip>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  )
}
