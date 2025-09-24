import { useEffect, useState } from "react"
import { Input } from "@/shared/components/Input"
import { Textarea } from "@/shared/components/Textarea"
import { Button } from "@/shared/components/Button"
import { Spinner } from "@/shared/components/Spinner"
import { useNotification } from "@/shared/hooks/useNotification"
import { trackEvent } from "@/shared/utils/telemetry"
import { updateKeyMetadata } from "@/services/vaultService"
import { KeyMetadata } from "@/types/vault"
import { clsx } from "clsx"

interface KeyMetadataEditorProps {
  keyId: string
  initialMetadata: KeyMetadata
  onUpdated?: (metadata: KeyMetadata) => void
  readonly?: boolean
}

export const KeyMetadataEditor = ({
  keyId,
  initialMetadata,
  onUpdated,
  readonly = false
}: KeyMetadataEditorProps) => {
  const [name, setName] = useState(initialMetadata.name)
  const [description, setDescription] = useState(initialMetadata.description || "")
  const [tags, setTags] = useState(initialMetadata.tags?.join(", ") || "")
  const [loading, setLoading] = useState(false)
  const [changed, setChanged] = useState(false)

  const { notifySuccess, notifyError } = useNotification()

  useEffect(() => {
    const metadataChanged =
      name !== initialMetadata.name ||
      description !== (initialMetadata.description || "") ||
      tags !== (initialMetadata.tags?.join(", ") || "")

    setChanged(metadataChanged)
  }, [name, description, tags, initialMetadata])

  const handleSave = async () => {
    setLoading(true)
    try {
      const updatedMetadata: KeyMetadata = {
        ...initialMetadata,
        name: name.trim(),
        description: description.trim(),
        tags: tags
          .split(",")
          .map(tag => tag.trim())
          .filter(Boolean)
      }

      await updateKeyMetadata(keyId, updatedMetadata)
      trackEvent("key_metadata_updated", { keyId })
      notifySuccess("Метаданные ключа обновлены")
      setChanged(false)
      onUpdated?.(updatedMetadata)
    } catch (err) {
      notifyError("Ошибка обновления метаданных")
      trackEvent("key_metadata_update_error", {
        keyId,
        error: String(err)
      })
    } finally {
      setLoading(false)
    }
  }

  const handleReset = () => {
    setName(initialMetadata.name)
    setDescription(initialMetadata.description || "")
    setTags(initialMetadata.tags?.join(", ") || "")
    setChanged(false)
  }

  return (
    <div className="space-y-6">
      <div className="space-y-2">
        <label className="text-sm font-semibold text-neutral-700 dark:text-neutral-200">Имя ключа</label>
        <Input
          value={name}
          onChange={e => setName(e.target.value)}
          disabled={readonly}
          placeholder="Уникальное имя ключа"
        />
      </div>

      <div className="space-y-2">
        <label className="text-sm font-semibold text-neutral-700 dark:text-neutral-200">Описание</label>
        <Textarea
          value={description}
          onChange={e => setDescription(e.target.value)}
          disabled={readonly}
          placeholder="Назначение, источник, контекст..."
        />
      </div>

      <div className="space-y-2">
        <label className="text-sm font-semibold text-neutral-700 dark:text-neutral-200">Теги</label>
        <Input
          value={tags}
          onChange={e => setTags(e.target.value)}
          disabled={readonly}
          placeholder="через запятую: backup, system, finance"
        />
      </div>

      {!readonly && (
        <div className="flex justify-end gap-3 pt-2">
          <Button
            variant="outline"
            onClick={handleReset}
            disabled={!changed || loading}
          >
            Сбросить
          </Button>
          <Button
            variant="primary"
            onClick={handleSave}
            disabled={!changed || loading}
            className={clsx("min-w-[160px]", loading && "opacity-60")}
          >
            {loading ? <Spinner size="sm" /> : "Сохранить изменения"}
          </Button>
        </div>
      )}
    </div>
  )
}
