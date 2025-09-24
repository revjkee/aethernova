// src/widgets/Voting/LiveVoteFeed.tsx

import React, { useEffect, useRef, useState } from 'react'
import { useSocket } from '@/shared/hooks/useSocket'
import { Spinner } from '@/shared/components/Spinner'
import { cn } from '@/shared/utils/classNames'
import { motion, AnimatePresence } from 'framer-motion'
import { useTheme } from '@/shared/hooks/useTelegramTheme'
import { useLatencyTracker } from '@/shared/hooks/useLatencyTracker'
import { AiInsightsOverlay } from '@/widgets/Voting/AiInsightsOverlay'

interface VoteMessage {
  id: string
  user: string
  choice: string
  timestamp: number
  avatarUrl?: string
}

const MAX_MESSAGES = 60

export const LiveVoteFeed: React.FC = () => {
  const [votes, setVotes] = useState<VoteMessage[]>([])
  const socket = useSocket('/votes')
  const { trackLatency } = useLatencyTracker('LiveVoteFeed')
  const feedRef = useRef<HTMLDivElement>(null)
  const { theme } = useTheme()

  useEffect(() => {
    if (!socket) return

    const handleVote = (msg: VoteMessage) => {
      trackLatency(msg.timestamp)
      setVotes(prev => {
        const updated = [msg, ...prev].slice(0, MAX_MESSAGES)
        return updated
      })
    }

    socket.on('vote_update', handleVote)
    return () => socket.off('vote_update', handleVote)
  }, [socket])

  useEffect(() => {
    if (!feedRef.current) return
    feedRef.current.scrollTop = 0
  }, [votes])

  return (
    <div
      ref={feedRef}
      className={cn(
        'h-full w-full overflow-y-auto p-4 bg-white dark:bg-gray-900 rounded-xl shadow-lg border',
        theme === 'dark' ? 'border-gray-700' : 'border-gray-200'
      )}
    >
      <h2 className="text-xl font-bold mb-4 text-center">Live Vote Feed</h2>

      <AnimatePresence initial={false}>
        {votes.map((vote) => (
          <motion.div
            key={vote.id}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, x: -20 }}
            transition={{ duration: 0.3 }}
            className="flex items-center mb-3 p-3 bg-gray-50 dark:bg-gray-800 rounded-lg shadow-sm"
          >
            {vote.avatarUrl ? (
              <img
                src={vote.avatarUrl}
                alt={vote.user}
                className="w-10 h-10 rounded-full mr-3 border border-gray-300 dark:border-gray-600"
              />
            ) : (
              <div className="w-10 h-10 mr-3 rounded-full bg-gradient-to-tr from-blue-400 to-purple-500 text-white flex items-center justify-center font-bold">
                {vote.user[0].toUpperCase()}
              </div>
            )}
            <div className="flex-1">
              <div className="text-sm font-medium">{vote.user}</div>
              <div className="text-xs text-gray-500 dark:text-gray-400">{vote.choice}</div>
            </div>
            <div className="text-xs text-right text-gray-400 ml-4">
              {new Date(vote.timestamp).toLocaleTimeString()}
            </div>
          </motion.div>
        ))}
      </AnimatePresence>

      {votes.length === 0 && (
        <div className="flex justify-center items-center h-40">
          <Spinner />
        </div>
      )}

      <AiInsightsOverlay votes={votes} />
    </div>
  )
}
