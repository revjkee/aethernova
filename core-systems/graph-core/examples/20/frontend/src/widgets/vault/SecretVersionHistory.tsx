import { useEffect, useState } from "react"
import { useSecretStore } from "@/state/secretStore"
import { getSecretHistory, rollbackSecretVersion } from "@/services/vaultService"
import { Spinner } from "@/shared/components/Spinner"
import { Button } from "@/shared/components/Button"
import { Modal } from "@/shared/components/Modal"
import { formatDate } from "@/shared/utils/date"
import { DiffViewer } from "@/shared/components/DiffViewer"
import { useNotification } from "@/shared/hooks/useNotification"
import { trackEvent } from "@/shared/utils/telemetry"
import clsx from "clsx"

interface SecretVersionHistoryProps {
  secretId: string
  onClose: () => void
  isOpen: boolean
}

export const SecretVersionHistory = ({ secretId, isOpen, onClose }: SecretVersionHistoryProps) => {
  const [history, setHistory] = useState<SecretVersion[]>([])
  const [loading, setLoading] = useState(false)
  const [selectedVersion, setSelectedVersion] = useState<SecretVersion | null>(null)
  const [currentVersion, setCurrentVersion] = useState<SecretVersion | null>(null)
  const [diffMode, setDiffMode] = useState(false)
  const [rollbacking, setRollbacking] = useState(false)

  const { notifySuccess, notifyError } = useNotification()
  const { refreshSecrets } = useSecretStore()

  useEffect(() => {
    if (isOpen) fetchHistory()
  }, [isOpen])

  const fetchHistory = async () => {
    setLoading(true)
    try {
      const versions = await getSecretHistory(secretId)
      setHistory(versions)
      setCurrentVersion(versions[0])
    } catch (err) {
      trackEvent("secret_history_error", { secretId, error: String(err) })
      notifyError("Не удалось загрузить историю версий")
    } finally {
      setLoading(false)
    }
  }

  const handleRollback = async (versionId: string) => {
    setRollbacking(true)
    try {
      await rollbackSecretVersion(secretId, versionId)
      trackEvent("secret_rollback", { secretId, toVersion: versionId })
      notifySuccess("Откат выполнен успешно")
      await fetchHistory()
    } catch (err) {
      trackEvent("secret_rollback_error", { secretId, error: String(err) })
      notifyError("Ошибка отката версии")
    } finally {
      setRollbacking(false)
    }
  }

  const renderVersionItem = (version: SecretVersion) => {
    const isCurrent = version.id === currentVersion?.id
    const isSelected = version.id === selectedVersion?.id

    return (
      <div
        key={version.id}
        className={clsx(
          "border rounded-md px-4 py-3 cursor-pointer transition-all",
          isSelected && "bg-blue-100 dark:bg-blue-900",
          isCurrent && "border-blue-600"
        )}
        onClick={() => setSelectedVersion(version)}
      >
        <div className="flex justify-between items-center">
          <div className="font-semibold text-sm text-neutral-700 dark:text-neutral-200">
            Версия: {version.version}
          </div>
          <div className="text-xs text-neutral-500 dark:text-neutral-400">
            {formatDate(version.createdAt)}
          </div>
        </div>
        <div className="text-xs mt-1 text-neutral-600 dark:text-neutral-300">
          Автор: {version.modifiedBy || "Неизвестно"}
        </div>
        {isSelected && !isCurrent && (
          <div className="flex justify-end mt-2">
            <Button
              size="sm"
              variant="danger"
              disabled={rollbacking}
              onClick={() => handleRollback(version.id)}
            >
              {rollbacking ? <Spinner size="xs" /> : "Откатить к этой версии"}
            </Button>
          </div>
        )}
      </div>
    )
  }

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="История версий секрета" size="xl">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 h-[500px] overflow-y-auto px-1 sm:px-3">
        <div className="space-y-3">
          {loading ? (
            <div className="flex justify-center items-center h-full">
              <Spinner size="lg" />
            </div>
          ) : history.length === 0 ? (
            <div className="text-center text-sm text-neutral-500 pt-6">История версий отсутствует</div>
          ) : (
            history.map(renderVersionItem)
          )}
        </div>

        <div className="md:col-span-2">
          {selectedVersion && currentVersion && (
            <>
              <div className="flex justify-between mb-2">
                <div className="text-sm font-medium">Сравнение версий</div>
                <Button size="xs" variant="outline" onClick={() => setDiffMode(!diffMode)}>
                  {diffMode ? "Скрыть различия" : "Показать различия"}
                </Button>
              </div>
              <DiffViewer
                oldValue={currentVersion?.content || ""}
                newValue={selectedVersion?.content || ""}
                splitView={true}
                showDiffOnly={diffMode}
              />
            </>
          )}
        </div>
      </div>
    </Modal>
  )
}
