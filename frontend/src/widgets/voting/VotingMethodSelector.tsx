// src/widgets/Voting/VotingMethodSelector.tsx

import React, { useEffect, useState } from 'react'
import { useZKAuth } from '@/shared/hooks/useZKAuth'
import { useVotingMethods } from '@/services/votingMethodService'
import { useTheme } from '@/shared/hooks/useTelegramTheme'
import { useAuditLogger } from '@/shared/hooks/useAuditLogger'
import { Spinner } from '@/shared/components/Spinner'
import { cn } from '@/shared/utils/classNames'
import { motion, AnimatePresence } from 'framer-motion'
import { VotingMethodInfoModal } from '@/widgets/Voting/VotingMethodInfoModal'
import { ShieldCheck, LockKeyhole } from 'lucide-react'

interface VotingMethod {
  id: string
  name: string
  description: string
  icon?: React.ReactNode
  secureLevel: 'zk' | 'token' | 'nft'
  active: boolean
}

interface Props {
  userId: string
  onSelect: (methodId: string) => void
}

export const VotingMethodSelector: React.FC<Props> = ({ userId, onSelect }) => {
  const { theme } = useTheme()
  const { verifyZKProof } = useZKAuth()
  const { getAvailableMethods } = useVotingMethods()
  const logAudit = useAuditLogger()

  const [methods, setMethods] = useState<VotingMethod[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [selectedMethod, setSelectedMethod] = useState<string | null>(null)
  const [showModal, setShowModal] = useState(false)

  useEffect(() => {
    const load = async () => {
      setLoading(true)
      try {
        const zkVerified = await verifyZKProof({ userId, purpose: 'voting_method_access' })
        if (!zkVerified) {
          setError('ZK-доступ запрещён.')
          return
        }

        const data = await getAvailableMethods(userId)
        setMethods(data)
      } catch (e) {
        setError('Ошибка загрузки методов голосования.')
      } finally {
        setLoading(false)
      }
    }

    load()
  }, [userId, verifyZKProof, getAvailableMethods])

  const handleSelect = (methodId: string) => {
    setSelectedMethod(methodId)
    logAudit({
      event: 'voting_method_selected',
      userId,
      timestamp: Date.now(),
      metadata: { methodId }
    })
    onSelect(methodId)
  }

  const secureColor = (level: string) => {
    switch (level) {
      case 'zk':
        return 'text-blue-600 dark:text-blue-300'
      case 'token':
        return 'text-green-600 dark:text-green-300'
      case 'nft':
        return 'text-purple-600 dark:text-purple-300'
      default:
        return 'text-gray-500'
    }
  }

  if (loading) {
    return (
      <div className="flex justify-center items-center h-32">
        <Spinner />
      </div>
    )
  }

  if (error) {
    return <div className="text-center text-sm text-red-500">{error}</div>
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35 }}
      className={cn(
        'rounded-lg p-4 border shadow-md space-y-3',
        theme === 'dark' ? 'bg-gray-900 border-gray-700' : 'bg-white border-gray-200'
      )}
    >
      <h3 className="text-lg font-semibold text-center">Выберите метод голосования</h3>

      <div className="space-y-3">
        <AnimatePresence initial={false}>
          {methods.map((method) => (
            <motion.button
              key={method.id}
              layout
              initial={{ opacity: 0, x: -12 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.25 }}
              onClick={() => handleSelect(method.id)}
              disabled={!method.active}
              className={cn(
                'w-full flex justify-between items-center px-4 py-3 rounded-md border text-sm shadow-sm transition-all',
                selectedMethod === method.id
                  ? 'border-blue-600 bg-blue-50 dark:bg-blue-800 text-blue-900 dark:text-white'
                  : 'border-gray-300 dark:border-gray-600 hover:border-blue-500',
                !method.active && 'opacity-50 cursor-not-allowed'
              )}
            >
              <div className="flex items-center gap-3 text-left">
                {method.icon ?? <LockKeyhole className="w-5 h-5" />}
                <div className="flex flex-col">
                  <span className="font-medium">{method.name}</span>
                  <span className="text-xs text-gray-500 dark:text-gray-400">{method.description}</span>
                </div>
              </div>
              <div className={cn('flex items-center gap-1 text-xs font-medium', secureColor(method.secureLevel))}>
                <ShieldCheck className="w-4 h-4" />
                {method.secureLevel.toUpperCase()}
              </div>
            </motion.button>
          ))}
        </AnimatePresence>
      </div>

      {selectedMethod && (
        <div className="text-center mt-4">
          <button
            onClick={() => setShowModal(true)}
            className="text-sm text-blue-600 dark:text-blue-300 hover:underline"
          >
            Подробнее о методе
          </button>
        </div>
      )}

      {showModal && selectedMethod && (
        <VotingMethodInfoModal
          methodId={selectedMethod}
          isOpen={showModal}
          onClose={() => setShowModal(false)}
        />
      )}
    </motion.div>
  )
}
