import { useRef, useEffect, useState } from "react"
import { createPortal } from "react-dom"
import { useOutsideClick } from "@/shared/hooks/useOutsideClick"
import { trackEvent } from "@/shared/utils/telemetry"
import { IconTrash, IconEdit, IconShare2, IconShield, IconKey, IconFolder, IconLock, IconMoreVertical } from "lucide-react"
import clsx from "clsx"

type VaultObjectType = "key" | "folder" | "secret" | "token" | "policy"
type VaultContextAction =
  | "edit"
  | "delete"
  | "rotate"
  | "share"
  | "permissions"
  | "history"
  | "copy"
  | "view"
  | "generate"
  | "revoke"

export interface VaultContextMenuAction {
  type: VaultContextAction
  label: string
  icon: React.ReactNode
  danger?: boolean
  confirm?: boolean
  disabled?: boolean
  children?: VaultContextMenuAction[]
  onClick?: () => void
}

interface VaultContextMenuProps {
  x: number
  y: number
  open: boolean
  objectType: VaultObjectType
  objectId: string
  permissions: string[]
  actions: VaultContextMenuAction[]
  onClose: () => void
}

export const VaultContextMenu = ({
  x,
  y,
  open,
  objectType,
  objectId,
  permissions,
  actions,
  onClose
}: VaultContextMenuProps) => {
  const ref = useRef<HTMLDivElement | null>(null)
  const [submenu, setSubmenu] = useState<null | { idx: number; rect: DOMRect }>(null)
  const [submenuPos, setSubmenuPos] = useState<{ left: number; top: number }>({ left: 0, top: 0 })

  useOutsideClick(ref, onClose)

  useEffect(() => {
    setSubmenu(null)
  }, [open, objectId])

  useEffect(() => {
    if (submenu && ref.current) {
      const item = ref.current.querySelectorAll<HTMLDivElement>("[data-menuitem]")[submenu.idx]
      if (item) {
        const rect = item.getBoundingClientRect()
        setSubmenuPos({ left: rect.right + 4, top: rect.top })
      }
    }
  }, [submenu])

  if (!open) return null

  // Корректировка позиций для выхода за экран
  const menuStyle: React.CSSProperties = {
    position: "fixed",
    left: x,
    top: y,
    zIndex: 9999,
    minWidth: 190,
    background: "var(--tw-bg-opacity, 1) #fff",
    borderRadius: 10,
    boxShadow: "0 8px 32px rgba(0,0,0,0.18)",
    border: "1px solid #d1d5db",
    padding: 4
  }

  const handleClick = (action: VaultContextMenuAction) => {
    if (action.disabled) return
    if (action.onClick) action.onClick()
    trackEvent("vault_context_menu_action", {
      objectType,
      objectId,
      action: action.type
    })
    onClose()
  }

  return createPortal(
    <div ref={ref} style={menuStyle} className={clsx("shadow-2xl bg-white dark:bg-neutral-900")}>
      {actions.map((action, idx) => (
        <div
          key={action.type}
          data-menuitem
          className={clsx(
            "flex items-center gap-2 px-3 py-2 text-sm cursor-pointer rounded transition-all select-none",
            action.danger
              ? "text-red-600 hover:bg-red-50 dark:hover:bg-red-900"
              : "text-neutral-800 dark:text-neutral-200 hover:bg-neutral-100 dark:hover:bg-neutral-800",
            action.disabled && "opacity-50 cursor-not-allowed"
          )}
          onClick={() => {
            if (action.children && action.children.length > 0) {
              setSubmenu({ idx, rect: ref.current?.getBoundingClientRect() || new DOMRect() })
            } else {
              handleClick(action)
            }
          }}
          onMouseEnter={() => {
            if (action.children && action.children.length > 0) {
              setSubmenu({ idx, rect: ref.current?.getBoundingClientRect() || new DOMRect() })
            } else {
              setSubmenu(null)
            }
          }}
        >
          {action.icon}
          <span className="flex-1">{action.label}</span>
          {action.children && <IconMoreVertical className="w-3 h-3 opacity-40" />}
        </div>
      ))}

      {/* Вложенное меню */}
      {submenu && actions[submenu.idx]?.children && (
        <div
          style={{
            position: "fixed",
            left: submenuPos.left,
            top: submenuPos.top,
            minWidth: 170,
            zIndex: 10000,
            background: "var(--tw-bg-opacity, 1) #fff",
            borderRadius: 10,
            boxShadow: "0 8px 32px rgba(0,0,0,0.12)",
            border: "1px solid #d1d5db",
            padding: 2
          }}
          className="shadow-xl bg-white dark:bg-neutral-900"
        >
          {actions[submenu.idx].children?.map((sub, sidx) => (
            <div
              key={sub.type}
              className={clsx(
                "flex items-center gap-2 px-3 py-2 text-sm cursor-pointer rounded select-none",
                sub.danger
                  ? "text-red-600 hover:bg-red-50 dark:hover:bg-red-900"
                  : "text-neutral-800 dark:text-neutral-200 hover:bg-neutral-100 dark:hover:bg-neutral-800",
                sub.disabled && "opacity-50 cursor-not-allowed"
              )}
              onClick={() => {
                if (!sub.disabled) {
                  if (sub.onClick) sub.onClick()
                  trackEvent("vault_context_menu_action", {
                    objectType,
                    objectId,
                    action: sub.type
                  })
                  onClose()
                }
              }}
            >
              {sub.icon}
              <span>{sub.label}</span>
            </div>
          ))}
        </div>
      )}
    </div>,
    document.body
  )
}

// Пример набора action-ов (вызывать в вызывающем компоненте):
export const getDefaultVaultActions = (
  type: VaultObjectType,
  perms: string[],
  handlers: Record<VaultContextAction, () => void>
): VaultContextMenuAction[] => {
  const actions: VaultContextMenuAction[] = []

  if (perms.includes("edit")) {
    actions.push({
      type: "edit",
      label: "Редактировать",
      icon: <IconEdit className="w-4 h-4" />,
      onClick: handlers.edit
    })
  }
  if (perms.includes("rotate") && type === "key") {
    actions.push({
      type: "rotate",
      label: "Ротировать ключ",
      icon: <IconRefreshCw className="w-4 h-4" />,
      confirm: true,
      onClick: handlers.rotate
    })
  }
  if (perms.includes("delete")) {
    actions.push({
      type: "delete",
      label: "Удалить",
      icon: <IconTrash className="w-4 h-4" />,
      danger: true,
      confirm: true,
      onClick: handlers.delete
    })
  }
  if (perms.includes("share")) {
    actions.push({
      type: "share",
      label: "Поделиться",
      icon: <IconShare2 className="w-4 h-4" />,
      onClick: handlers.share
    })
  }
  if (perms.includes("permissions")) {
    actions.push({
      type: "permissions",
      label: "Права доступа",
      icon: <IconShield className="w-4 h-4" />,
      children: [
        {
          type: "view",
          label: "Просмотреть права",
          icon: <IconShield className="w-4 h-4" />,
          onClick: handlers.permissions
        },
        {
          type: "generate",
          label: "Сгенерировать токен",
          icon: <IconKey className="w-4 h-4" />,
          onClick: handlers.generate
        }
      ]
    })
  }
  // ... другие действия по необходимости
  return actions
}
