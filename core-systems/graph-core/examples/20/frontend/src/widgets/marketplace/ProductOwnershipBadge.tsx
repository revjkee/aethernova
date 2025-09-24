import React, { useEffect, useState } from "react"
import { fetchOwnershipMetadata } from "@/features/marketplace/api/fetchOwnershipMetadata"
import { Avatar } from "@/shared/components/Avatar"
import { Badge } from "@/shared/components/Badge"
import { cn } from "@/shared/utils/classNames"
import { shortenAddress } from "@/shared/utils/address"
import { ExternalLink } from "lucide-react"
import { Skeleton } from "@/shared/components/Skeleton"
import { Link } from "react-router-dom"
import { useUser } from "@/features/auth/hooks/useUser"

interface Props {
  productId: string
  className?: string
}

interface OwnershipInfo {
  ownerAddress: string
  ownerType: "user" | "nft" | "dao" | "contract"
  displayName: string
  avatarUrl?: string
  verified: boolean
  explorerUrl?: string
  role?: string
}

export const ProductOwnershipBadge: React.FC<Props> = ({ productId, className }) => {
  const { user } = useUser()
  const [data, setData] = useState<OwnershipInfo | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true)
      try {
        const result = await fetchOwnershipMetadata(productId)
        setData(result)
      } catch (err) {
        console.error("OwnershipBadge error:", err)
      } finally {
        setLoading(false)
      }
    }

    fetchData()
  }, [productId])

  if (loading) {
    return (
      <div className={cn("flex items-center gap-2", className)}>
        <Skeleton className="h-6 w-6 rounded-full" />
        <Skeleton className="h-4 w-24" />
      </div>
    )
  }

  if (!data) return null

  const {
    ownerAddress,
    ownerType,
    displayName,
    avatarUrl,
    verified,
    explorerUrl,
    role
  } = data

  const typeColorMap: Record<OwnershipInfo["ownerType"], "default" | "info" | "success" | "destructive"> = {
    user: "default",
    nft: "success",
    dao: "info",
    contract: "destructive"
  }

  return (
    <div className={cn("flex items-center gap-3", className)}>
      <Avatar src={avatarUrl} fallback={displayName.charAt(0)} size="sm" />
      <div className="flex flex-col">
        <div className="flex items-center gap-1">
          <span className="font-medium text-sm">{displayName}</span>
          {verified && (
            <Badge variant="success" className="text-[10px] px-1.5 py-0.5">
              Verified
            </Badge>
          )}
        </div>
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <Badge variant={typeColorMap[ownerType]}>
            {ownerType.toUpperCase()}
          </Badge>
          {role && (
            <Badge variant="secondary" className="ml-1">
              Role: {role}
            </Badge>
          )}
          {explorerUrl && (
            <a
              href={explorerUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="ml-2 flex items-center gap-1 hover:underline text-primary"
            >
              <ExternalLink size={12} />
              {shortenAddress(ownerAddress)}
            </a>
          )}
        </div>
      </div>
      {user?.address === ownerAddress && (
        <Link
          to={`/ownership/manage/${productId}`}
          className="ml-auto text-xs underline text-muted-foreground hover:text-primary"
        >
          Управление
        </Link>
      )}
    </div>
  )
}
