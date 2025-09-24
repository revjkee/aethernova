import React, { useEffect, useState } from 'react';
import { Tooltip } from '@/shared/components/Tooltip';
import { OverrideIcon } from '@/shared/components/icons/OverrideIcon';
import { fetchOverrideInfo } from '@/features/agents/api/override';
import { useTheme } from '@/shared/hooks/useThemeSwitcher';
import { Spinner } from '@/shared/components/Spinner';
import './styles/AgentOverrideFlag.css';

interface AgentOverrideFlagProps {
  agentId: string;
}

interface OverrideMetadata {
  isActive: boolean;
  reason: string;
  overriddenBy: string;
  timestamp: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

export const AgentOverrideFlag: React.FC<AgentOverrideFlagProps> = ({ agentId }) => {
  const { theme } = useTheme();
  const [data, setData] = useState<OverrideMetadata | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    fetchOverrideInfo(agentId).then((info) => {
      if (mounted) {
        setData(info);
        setLoading(false);
      }
    });
    return () => {
      mounted = false;
    };
  }, [agentId]);

  if (loading) {
    return (
      <div className={`agent-override-flag loading ${theme}`}>
        <Spinner size="small" />
      </div>
    );
  }

  if (!data || !data.isActive) {
    return null;
  }

  const colorClass = `severity-${data.severity}`;

  return (
    <div className={`agent-override-flag ${theme} ${colorClass}`}>
      <Tooltip
        content={
          <div className="tooltip-content">
            <div><strong>Переопределено вручную</strong></div>
            <div>Оператор: {data.overriddenBy}</div>
            <div>Причина: {data.reason}</div>
            <div>Время: {new Date(data.timestamp).toLocaleString('ru-RU')}</div>
            <div>Критичность: {data.severity.toUpperCase()}</div>
          </div>
        }
      >
        <div className="flag-indicator">
          <OverrideIcon severity={data.severity} />
          <span className="flag-text">Override</span>
        </div>
      </Tooltip>
    </div>
  );
};
