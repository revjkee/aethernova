import { useEffect, useState } from "react"
import { getAssignableRoles, getCurrentAssignments, assignRoleToTarget, revokeRoleFromTarget } from "@/services/rolesService"
import { RoleAssignment } from "@/types/roles"
import { Select } from "@/shared/components/Select"
import { Button } from "@/shared/components/Button"
import { Spinner } from "@/shared/components/Spinner"
import { Input } from "@/shared/components/Input"
import { useNotification } from "@/shared/hooks/useNotification"
import { trackEvent } from "@/shared/utils/telemetry"
import { ConfirmModal } from "@/shared/components/ConfirmModal"
import clsx from "clsx"

interface VaultRoleAssignmentProps {
  targetId: string
  targetType: "key" | "folder"
  readonly?: boolean
}

export const VaultRoleAssignment = ({
  targetId,
  targetType,
  readonly = false
}: VaultRoleAssignmentProps) => {
  const [availableRoles, setAvailableRoles] = useState<string[]>([])
  const [assignments, setAssignments] = useState<RoleAssignment[]>([])
  const [loading, setLoading] = useState(false)
  const [newRole, setNewRole] = useState("")
  const [userInput, setUserInput] = useState("")
  const [revokingId, setRevokingId] = useState<string | null>(null)

  const { notifySuccess, notifyError } = useNotification()

  useEffect(() => {
    fetchData()
  }, [targetId, targetType])

  const fetchData = async () => {
    setLoading(true)
    try {
      const [roles, current] = await Promise.all([
        getAssignableRoles(),
        getCurrentAssignments(targetId, targetType)
      ])
      setAvailableRoles(roles)
      setAssignments(current)
      trackEvent("vault_role_view_loaded", { targetId, targetType })
    } catch (err) {
      notifyError("Ошибка загрузки ролей")
      trackEvent("vault_role_view_error", {
        error: String(err),
        targetId
      })
    } finally {
      setLoading(false)
    }
  }

  const handleAssign = async () => {
    if (!userInput || !newRole) return
    setLoading(true)
    try {
      await assignRoleToTarget(targetId, userInput.trim(), newRole, targetType)
      notifySuccess("Роль успешно назначена")
      trackEvent("vault_role_assigned", { targetId, actor: userInput, role: newRole })
      setUserInput("")
      setNewRole("")
      await fetchData()
    } catch (err) {
      notifyError("Ошибка назначения роли")
      trackEvent("vault_role_assign_error", {
        targetId,
        error: String(err)
      })
    } finally {
      setLoading(false)
    }
  }

  const handleRevoke = async (assignmentId: string) => {
    setRevokingId(assignmentId)
    try {
      await revokeRoleFromTarget(assignmentId)
      notifySuccess("Роль отозвана")
      trackEvent("vault_role_revoked", { assignmentId, targetId })
      await fetchData()
    } catch (err) {
      notifyError("Ошибка при отзыве роли")
      trackEvent("vault_role_revoke_error", { assignmentId, error: String(err) })
    } finally {
      setRevokingId(null)
    }
  }

  return (
    <div className="space-y-6">
      <div className="space-y-3">
        <div className="text-lg font-semibold text-neutral-800 dark:text-neutral-100">
          Текущие назначения
        </div>
        {loading ? (
          <div className="flex justify-center py-6"><Spinner size="lg" /></div>
        ) : assignments.length === 0 ? (
          <div className="text-neutral-500 text-sm">Назначения отсутствуют</div>
        ) : (
          <ul className="space-y-2">
            {assignments.map((a) => (
              <li key={a.id} className="flex items-center justify-between border px-4 py-2 rounded-md bg-neutral-50 dark:bg-neutral-900">
                <div className="space-y-0.5">
                  <div className="text-sm font-medium text-neutral-800 dark:text-neutral-100">
                    {a.actor}
                  </div>
                  <div className="text-xs text-neutral-500 dark:text-neutral-400">
                    Роль: {a.role}
                  </div>
                </div>
                {!readonly && (
                  <Button
                    variant="danger"
                    size="xs"
                    disabled={revokingId === a.id}
                    onClick={() => handleRevoke(a.id)}
                  >
                    {revokingId === a.id ? <Spinner size="xs" /> : "Отозвать"}
                  </Button>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>

      {!readonly && (
        <div className="border-t pt-6 space-y-3">
          <div className="text-lg font-semibold text-neutral-800 dark:text-neutral-100">
            Назначить новую роль
          </div>
          <div className="flex flex-col sm:flex-row gap-4">
            <Input
              placeholder="Пользователь / Агент"
              value={userInput}
              onChange={(e) => setUserInput(e.target.value)}
              className="flex-1"
            />
            <Select
              options={availableRoles.map((r) => ({ label: r, value: r }))}
              value={newRole}
              onChange={setNewRole}
              placeholder="Выберите роль"
              className="min-w-[200px]"
            />
            <Button
              variant="primary"
              onClick={handleAssign}
              disabled={!newRole || !userInput}
              className="min-w-[140px]"
            >
              Назначить
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}
