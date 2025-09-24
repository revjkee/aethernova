import React, { useEffect, useRef, useState, useCallback } from 'react'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { useSSE } from '@/hooks/useSSE'
import { ChevronDown, AlertCircle, CheckCircle, RefreshCw } from 'lucide-react'
import clsx from 'clsx'

interface ExplanationEvent {
  id: string
  timestamp: string
  model: string
  userId: string
  explanation: string
  trustScore: number
  category: 'default' | 'bias' | 'non-transparent' | 'risk' | 'error'
  critical: boolean
}

const explanationColor = {
  default: 'border-muted',
  bias: 'border-yellow-500',
  non-transparent: 'border-blue-500',
  risk: 'border-red-500',
  error: 'border-destructive',
}

export const RealTimeExplanationFeed: React.FC = () => {
  const [events, setEvents] = useState<ExplanationEvent[]>([])
  const [autoScroll, setAutoScroll] = useState(true)
  const bottomRef = useRef<HTMLDivElement | null>(null)

  const onNewEvent = useCallback((event: ExplanationEvent) => {
    setEvents((prev) => [...prev.slice(-99), event])
  }, [])

  const { isConnected, isLoading } = useSSE<ExplanationEvent>({
    url: '/api/xai/feed',
    onMessage: onNewEvent,
    retry: true,
  })

  useEffect(() => {
    if (autoScroll && bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [events, autoScroll])

  return (
    <div className="relative w-full h-[640px] rounded-md border bg-background shadow-sm overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2 border-b bg-muted">
        <div className="font-semibold text-sm flex items-center gap-2">
          <RefreshCw
            className={clsx(
              'h-4 w-4 animate-spin',
              isConnected ? 'text-green-600' : 'text-gray-400'
            )}
          />
          XAI Stream
        </div>
        <button
          className="text-xs text-muted-foreground hover:underline"
          onClick={() => setAutoScroll((p) => !p)}
        >
          {autoScroll ? 'Auto-scroll: ON' : 'Auto-scroll: OFF'}
        </button>
      </div>

      <ScrollArea className="h-full">
        <div className="flex flex-col p-3 space-y-2 text-sm font-mono">
          {isLoading && <Skeleton className="h-4 w-full" />}
          {events.map((ev) => (
            <div
              key={ev.id}
              className={clsx(
                'px-3 py-2 border-l-4 rounded-sm transition-colors duration-200',
                explanationColor[ev.category],
                ev.critical && 'bg-red-50'
              )}
            >
              <div className="flex justify-between">
                <div className="text-xs text-muted-foreground">{ev.timestamp}</div>
                {ev.critical && (
                  <Badge variant="destructive" className="flex items-center gap-1 h-5 px-2">
                    <AlertCircle className="w-3 h-3" />
                    CRITICAL
                  </Badge>
                )}
              </div>
              <div className="font-semibold text-sm">{ev.model}</div>
              <div className="text-xs text-muted-foreground">User: {ev.userId}</div>
              <div className="mt-1 whitespace-pre-wrap text-[13px] leading-snug">{ev.explanation}</div>
              <div className="flex justify-end pt-1">
                <Badge variant="outline" className="flex items-center gap-1 px-2 py-0 h-5 text-xs">
                  Trust: {ev.trustScore.toFixed(2)}%
                  {ev.trustScore > 80 ? (
                    <CheckCircle className="w-3 h-3 text-green-500" />
                  ) : (
                    <AlertCircle className="w-3 h-3 text-yellow-500" />
                  )}
                </Badge>
              </div>
            </div>
          ))}
          <div ref={bottomRef} />
        </div>
      </ScrollArea>

      {!isConnected && (
        <div className="absolute inset-0 bg-background/90 flex items-center justify-center text-sm text-muted-foreground">
          Ожидание подключения к XAI потоку…
        </div>
      )}
    </div>
  )
}
