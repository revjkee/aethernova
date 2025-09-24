import React, { useEffect, useState } from "react"
import { Badge } from "@/shared/components/Badge"
import { formatDate } from "@/shared/utils/datetime"
import { SubscriptionType, SubscriptionStatus } from "@/features/subscriptions/types"
import { fetchSubscriptionStatus } from "@/features/subscriptions/api/fetchSubscriptionStatus"
import { Loader } from "@/shared/components/Loader"
import { useUser } from "@/features/auth/hooks/useUser"
import { cn } from "@/shared/utils/classNames"
import { Link } from "react-router-dom"

interface Props {
  productId: string
  className?: string
}

interface SubscriptionData {
  status: SubscriptionStatus
  type: SubscriptionType
  expiresAt: number
  autoRenew: boolean
}

export const MarketplaceSubscriptionBadge: React.FC<Props> = ({ productId, className }) => {
  const { user } = useUser()
  const [loading, setLoading] = useState(true)
  const [data, setData] = useState<SubscriptionData | null>(null)

  useEffect(() => {
    if (!user?.id) return

    const fetchData = async () => {
      setLoading(true)
      try {
        const result = await fetchSubscriptionStatus(user.id, productId)
        setData(result)
      } catch (e) {
        console.error("SubscriptionBadge error:", e)
      } finally {
        setLoading(false)
      }
    }

    fetchData()
  }, [user?.id, productId])

  if (loading) return <Loader className={cn("h-5", className)} />

  if (!data) return null

  const { status, expiresAt, type, autoRenew } = data

  const statusLabel = {
    active: "Активна",
    expired: "Истекла",
    pending: "Ожидает активации"
  }[status]

  const badgeColor = {
    active: "success",
    expired: "destructive",
    pending: "warning"
  }[status]

  return (
    <div className={cn("flex items-center gap-2", className)}>
      <Badge variant={badgeColor}>
        Подписка: {statusLabel}
      </Badge>
      <span className="text-sm text-muted-foreground">
        {status === "active" && <>до {formatDate(expiresAt)}</>}
        {status === "expired" && <>истекла {formatDate(expiresAt)}</>}
        {status === "pending" && <>ожидает подтверждения</>}
      </span>
      {type === "recurring" && (
        <span className="ml-2 text-xs italic text-muted-foreground">
          {autoRenew ? "Auto-renew" : "Manual renew"}
        </span>
      )}
      <Link
        to={`/subscriptions/manage/${productId}`}
        className="ml-auto text-xs underline text-primary hover:text-primary-dark"
      >
        Управление
      </Link>
    </div>
  )
}
