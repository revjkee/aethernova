import React, { useEffect, useState } from "react"
import { cn } from "@/shared/utils/classNames"
import { shortenAddress } from "@/shared/utils/address"
import { getExplorerLink } from "@/shared/utils/blockchain"
import { Tooltip } from "@/shared/components/Tooltip"
import { ExternalLink, CheckCircle2, AlertCircle, Loader2 } from "lucide-react"
import { Badge } from "@/shared/components/Badge"
import { Skeleton } from "@/shared/components/Skeleton"

interface Props {
  contractAddress: string
  chainId: number
  offerId?: string
  className?: string
}

interface ContractValidationResult {
  valid: boolean
  type: "Offer" | "ERC721" | "ERC1155" | "Custom"
  metadata?: {
    name?: string
    symbol?: string
    decimals?: number
  }
}

export const OnchainOfferLink: React.FC<Props> = ({
  contractAddress,
  chainId,
  offerId,
  className
}) => {
  const [validation, setValidation] = useState<ContractValidationResult | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const validate = async () => {
      setLoading(true)
      try {
        const res = await fetch(`/api/onchain/validate?address=${contractAddress}&chainId=${chainId}`)
        const json = await res.json()
        setValidation(json)
      } catch (e) {
        console.error("Contract validation failed", e)
        setValidation(null)
      } finally {
        setLoading(false)
      }
    }
    validate()
  }, [contractAddress, chainId])

  const explorerLink = getExplorerLink(chainId, contractAddress)

  return (
    <div className={cn("flex items-center gap-2", className)}>
      {loading ? (
        <Skeleton className="h-5 w-40 rounded" />
      ) : validation ? (
        <>
          <a
            href={explorerLink}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center text-sm text-primary hover:underline gap-1"
          >
            <ExternalLink size={14} />
            {shortenAddress(contractAddress)}
          </a>
          <Tooltip
            content={
              <div className="text-xs">
                Тип: {validation.type}
                <br />
                Сеть: {chainId}
                {validation.metadata?.name && (
                  <>
                    <br />
                    Name: {validation.metadata.name}
                  </>
                )}
                {validation.metadata?.symbol && (
                  <>
                    <br />
                    Symbol: {validation.metadata.symbol}
                  </>
                )}
              </div>
            }
          >
            <Badge variant={validation.valid ? "success" : "destructive"}>
              {validation.valid ? (
                <div className="flex items-center gap-1">
                  <CheckCircle2 size={12} />
                  Valid
                </div>
              ) : (
                <div className="flex items-center gap-1">
                  <AlertCircle size={12} />
                  Invalid
                </div>
              )}
            </Badge>
          </Tooltip>
        </>
      ) : (
        <div className="flex items-center text-sm text-destructive gap-1">
          <AlertCircle size={14} />
          Неверный контракт
        </div>
      )}
    </div>
  )
}
