import React, { useEffect, useState } from 'react';
import { useTheme } from '@/shared/hooks/useThemeSwitcher';
import { useSocket } from '@/shared/hooks/useSocket';
import { Spinner } from '@/shared/components/Spinner';
import './styles/AgentConsciousnessTrace.css';

interface TraceStep {
  timestamp: number;
  thought: string;
  rationale: string;
  type: 'perception' | 'logic' | 'memory' | 'ethics' | 'planning' | 'contradiction';
  confidence: number;
}

interface AgentConsciousnessTraceProps {
  agentId: string;
  maxSteps?: number;
  compact?: boolean;
}

export const AgentConsciousnessTrace: React.FC<AgentConsciousnessTraceProps> = ({
  agentId,
  maxSteps = 25,
  compact = false,
}) => {
  const { theme } = useTheme();
  const [trace, setTrace] = useState<TraceStep[]>([]);
  const [loading, setLoading] = useState(true);
  const { connect, disconnect } = useSocket(`/agents/${agentId}/consciousness_trace`);

  useEffect(() => {
    const socket = connect((event) => {
      const steps: TraceStep[] = JSON.parse(event.data);
      setTrace(steps.slice(-maxSteps).reverse());
      setLoading(false);
    });
    return () => disconnect(socket);
  }, [agentId, maxSteps]);

  if (loading) {
    return <div className="consciousness-trace loading"><Spinner size="medium" /></div>;
  }

  const getColorByType = (type: TraceStep['type']) => {
    switch (type) {
      case 'perception': return '#1e88e5';
      case 'logic': return '#43a047';
      case 'memory': return '#6d4c41';
      case 'ethics': return '#8e24aa';
      case 'planning': return '#fb8c00';
      case 'contradiction': return '#e53935';
    }
  };

  return (
    <div className={`consciousness-trace-container ${theme} ${compact ? 'compact' : ''}`}>
      {trace.map((step, index) => (
        <div key={index} className="trace-step">
          <div className="timestamp">
            {new Date(step.timestamp).toLocaleTimeString('ru-RU')}
          </div>
          <div
            className="thought-block"
            style={{ borderLeftColor: getColorByType(step.type) }}
          >
            <div className="thought">{step.thought}</div>
            <div className="rationale">{step.rationale}</div>
            <div className="meta">
              <span className="type-label">{step.type}</span>
              <span className="confidence-label">
                {Math.round(step.confidence * 100)}%
              </span>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
};
