import { useEffect, useState } from "react"
import { verifyZKProof } from "@/services/zkVerifierService"
import { ZKProofResult } from "@/types/zk"
import { Spinner } from "@/shared/components/Spinner"
import { Tooltip } from "@/shared/components/Tooltip"
import { Badge } from "@/shared/components/Badge"
import { IconCheckCircle, IconAlertTriangle, IconLoader2, IconXCircle, IconShield } from "lucide-react"
import { trackEvent } from "@/shared/utils/telemetry"
import clsx from "clsx"

interface VaultZKProofVerifierProps {
  proofId: string
  context: string
  minimal?: boolean
}

export const VaultZKProofVerifier = ({
  proofId,
  context,
  minimal = false
}: VaultZKProofVerifierProps) => {
  const [result, setResult] = useState<ZKProofResult | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    handleVerify()
  }, [proofId, context])

  const handleVerify = async () => {
    setLoading(true)
    try {
      const res = await verifyZKProof(proofId, context)
      setResult(res)
      trackEvent("zk_proof_verified", { proofId, result: res.valid ? "valid" : "invalid" })
    } catch (err) {
      setError("Ошибка при проверке ZK-доказательства")
      setResult(null)
      trackEvent("zk_proof_verification_error", { proofId, error: String(err) })
    } finally {
      setLoading(false)
    }
  }

  const renderStatus = () => {
    if (loading) {
      return (
        <div className="flex items-center gap-2 text-blue-600">
          <IconLoader2 className="animate-spin w-4 h-4" />
          <span className="text-sm">Проверка доказательства...</span>
        </div>
      )
    }

    if (error) {
      return (
        <div className="flex items-center gap-2 text-red-600">
          <IconXCircle className="w-4 h-4" />
          <span className="text-sm">{error}</span>
        </div>
      )
    }

    if (!result) {
      return null
    }

    return result.valid ? (
      <div className="flex items-center gap-2 text-green-600">
        <IconCheckCircle className="w-4 h-4" />
        <span className="text-sm">Доказательство подтверждено</span>
      </div>
    ) : (
      <div className="flex items-center gap-2 text-yellow-600">
        <IconAlertTriangle className="w-4 h-4" />
        <span className="text-sm">Доказательство не прошло проверку</span>
      </div>
    )
  }

  const renderDetails = () => {
    if (!result || loading || error || minimal) return null

    return (
      <div className="grid grid-cols-2 gap-4 text-xs text-neutral-600 dark:text-neutral-400 pt-3">
        <div>
          <div className="font-medium text-neutral-800 dark:text-neutral-200">Параметры</div>
          <div className="mt-1">{JSON.stringify(result.parameters)}</div>
        </div>
        <div>
          <div className="font-medium text-neutral-800 dark:text-neutral-200">Контекст</div>
          <div className="mt-1 break-words">{context}</div>
        </div>
      </div>
    )
  }

  return (
    <div className="border rounded-lg p-4 bg-white dark:bg-neutral-900 shadow-sm">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <IconShield className="w-5 h-5 text-purple-600" />
          <span className="font-semibold text-neutral-900 dark:text-neutral-100 text-sm">
            Верификация Zero-Knowledge доступа
          </span>
        </div>
        {result && (
          <Badge variant={result.valid ? "success" : "danger"}>
            {result.valid ? "VALID" : "INVALID"}
          </Badge>
        )}
      </div>

      <div className="pt-3">{renderStatus()}</div>
      {renderDetails()}
    </div>
  )
}
