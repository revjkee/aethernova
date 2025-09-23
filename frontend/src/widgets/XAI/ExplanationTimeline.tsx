// src/widgets/XAI/ExplanationTimeline.tsx

import React, { useEffect, useState, useMemo } from 'react'
import { Timeline, TimelineItem } from '@/shared/ui/Timeline'
import { useXAIContext } from '@/shared/context/XAIContext'
import { getExplanationHistory, ExplanationEvent } from '@/services/xai/explanationTracker'
import { Card } from '@/shared/ui/Card'
import { Badge } from '@/shared/ui/Badge'
import { Icon } from '@/shared/ui/Icon'
import { formatTimestamp } from '@/shared/utils/format'
import { ExplanationDetailsDrawer } from './ExplanationDetailsDrawer'
import './ExplanationTimeline.css'

interface ExplanationTimelineProps {
  decisionId: string
}

export const ExplanationTimeline: React.FC<ExplanationTimelineProps> = ({ decisionId }) => {
  const { triggerGlobalAlert } = useXAIContext()
  const [events, setEvents] = useState<ExplanationEvent[]>([])
  const [loading, setLoading] = useState(false)
  const [selectedEvent, setSelectedEvent] = useState<ExplanationEvent | null>(null)

  useEffect(() => {
    const loadHistory = async () => {
      setLoading(true)
      try {
        const history = await getExplanationHistory(decisionId)
        setEvents(history)
      } catch (err) {
        triggerGlobalAlert('Не удалось загрузить историю объяснений', 'error')
      } finally {
        setLoading(false)
      }
    }
    loadHistory()
  }, [decisionId, triggerGlobalAlert])

  const timelineItems: TimelineItem[] = useMemo(
    () =>
      events.map((event, idx) => ({
        key: `${event.timestamp}-${idx}`,
        timestamp: formatTimestamp(event.timestamp),
        title: event.eventType,
        description: event.summary,
        icon: resolveIcon(event.eventType),
        onClick: () => setSelectedEvent(event),
        color: resolveColor(event.confidence)
      })),
    [events]
  )

  return (
    <div className="explanation-timeline-container">
      <h2 className="timeline-title">Хронология объяснений</h2>
      {loading ? (
        <div className="loading-indicator">Загрузка...</div>
      ) : (
        <Timeline items={timelineItems} />
      )}
      {selectedEvent && (
        <ExplanationDetailsDrawer
          event={selectedEvent}
          onClose={() => setSelectedEvent(null)}
        />
      )}
    </div>
  )
}

// ——————————————————————————————————————————————————————
// Утилиты визуализации
// ——————————————————————————————————————————————————————

function resolveIcon(eventType: string): React.ReactNode {
  switch (eventType) {
    case 'ModelChanged':
      return <Icon name="cpu" />
    case 'ConfidenceDrop':
      return <Icon name="alert-triangle" />
    case 'CounterfactualSuggested':
      return <Icon name="shuffle" />
    case 'RuleChainUpdate':
      return <Icon name="settings" />
    default:
      return <Icon name="info" />
  }
}

function resolveColor(confidence: number): string {
  if (confidence > 0.85) return 'green'
  if (confidence > 0.5) return 'orange'
  return 'red'
}
