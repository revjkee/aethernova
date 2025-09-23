// src/widgets/Agents/AgentTrustScore.tsx
import React, { useEffect, useState, useMemo } from 'react';
import { useTheme } from '@/shared/hooks/useThemeSwitcher';
import { useTrustInference } from '@/features/agents/hooks/useTrustInference';
import { useSocket } from '@/shared/hooks/useSocket';
import { Spinner } from '@/shared/components/Spinner';
import { Tooltip } from '@/shared/components/Tooltip';
import { RiskGraph } from '@/widgets/Agents/components/RiskGraph';
import { Gauge } from '@/widgets/Agents/components/Gauge';
import './AgentTrustScore.css';

interface AgentTrustScoreProps {
  agentId: string;
}

export const AgentTrustScore: React.FC<AgentTrustScoreProps> = ({ agentId }) => {
  const { theme } = useTheme();
  const [trustScore, setTrustScore] = useState<number | null>(null);
  const [riskLevel, setRiskLevel] = useState<number>(0);
  const [loading, setLoading] = useState(true);
  const { connect, disconnect } = useSocket(`/agents/${agentId}/trust`);
  const { fetchTrustData } = useTrustInference();

  useEffect(() => {
    let mounted = true;
    const init = async () => {
      setLoading(true);
      const data = await fetchTrustData(agentId);
      if (mounted && data) {
        setTrustScore(data.trust);
        setRiskLevel(data.risk);
        setLoading(false);
      }
    };

    init();
    const socket = connect((event) => {
      const payload = JSON.parse(event.data);
      if (payload.trust !== undefined) setTrustScore(payload.trust);
      if (payload.risk !== undefined) setRiskLevel(payload.risk);
    });

    return () => {
      mounted = false;
      disconnect(socket);
    };
  }, [agentId]);

  const trustLabel = useMemo(() => {
    if (trustScore === null) return 'Недоступно';
    if (trustScore > 80) return 'Высокое доверие';
    if (trustScore > 50) return 'Умеренное доверие';
    if (trustScore >= 0) return 'Низкое доверие';
    return 'Ошибка';
  }, [trustScore]);

  if (loading) {
    return (
      <div className="agent-trust-score loading">
        <Spinner />
        <span>Загрузка оценки доверия...</span>
      </div>
    );
  }

  return (
    <div className={`agent-trust-score ${theme}`}>
      <div className="header">
        <h3>Уровень доверия к агенту</h3>
        <Tooltip content="AI-модель анализирует поведение агента, его связи и последние действия для оценки уровня доверия и риска.">
          <span className="info-icon">?</span>
        </Tooltip>
      </div>

      <Gauge value={trustScore ?? 0} label={trustLabel} max={100} />

      <div className="meta-section">
        <RiskGraph riskLevel={riskLevel} />
      </div>
    </div>
  );
};
