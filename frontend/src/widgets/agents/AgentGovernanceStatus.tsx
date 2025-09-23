import React, { useEffect, useState } from 'react';
import { useTheme } from '@/shared/hooks/useThemeSwitcher';
import { useSocket } from '@/shared/hooks/useSocket';
import { Spinner } from '@/shared/components/Spinner';
import { GovernanceIcon } from '@/shared/components/icons/GovernanceIcon';
import { TrustLevelIndicator } from '@/widgets/Agents/components/TrustLevelIndicator';
import { DelegationStatus } from '@/widgets/Agents/components/DelegationStatus';
import { Alert } from '@/shared/components/Alert';
import './styles/AgentGovernanceStatus.css';

interface GovernanceStatusPayload {
  timestamp: number;
  isSubordinate: boolean;
  mentorAgentId: string | null;
  hierarchyLevel: number;
  trustScore: number;
  delegationLevel: 'none' | 'partial' | 'full';
  controlIntegrity: 'verified' | 'uncertain' | 'compromised';
}

interface AgentGovernanceStatusProps {
  agentId: string;
}

export const AgentGovernanceStatus: React.FC<AgentGovernanceStatusProps> = ({ agentId }) => {
  const { theme } = useTheme();
  const [status, setStatus] = useState<GovernanceStatusPayload | null>(null);
  const [loading, setLoading] = useState(true);
  const { connect, disconnect } = useSocket(`/agents/${agentId}/governance`);

  useEffect(() => {
    let mounted = true;
    const socket = connect((event) => {
      const payload: GovernanceStatusPayload = JSON.parse(event.data);
      if (!mounted) return;
      setStatus(payload);
      setLoading(false);
    });

    return () => {
      mounted = false;
      disconnect(socket);
    };
  }, [agentId]);

  if (loading || !status) {
    return (
      <div className="agent-governance-status loading">
        <Spinner />
        <span>Загрузка статуса подчинения...</span>
      </div>
    );
  }

  const hierarchyLabel = (): string => {
    if (!status.isSubordinate) return 'Автономный режим';
    switch (status.hierarchyLevel) {
      case 1: return 'Прямое подчинение';
      case 2: return 'Каскадное подчинение';
      default: return `Иерархия ${status.hierarchyLevel}-го уровня`;
    }
  };

  return (
    <div className={`agent-governance-status ${theme}`}>
      <div className="header">
        <h3>Статус подчинённости агента</h3>
        <GovernanceIcon />
      </div>

      <div className="grid">
        <div className="block">
          <span className="label">Наставник:</span>
          <span className="value">
            {status.mentorAgentId ?? '—'}
          </span>
        </div>
        <div className="block">
          <span className="label">Иерархия:</span>
          <span className="value">
            {hierarchyLabel()}
          </span>
        </div>
        <div className="block">
          <span className="label">Делегирование:</span>
          <DelegationStatus level={status.delegationLevel} />
        </div>
        <div className="block">
          <span className="label">Доверие:</span>
          <TrustLevelIndicator score={status.trustScore} />
        </div>
        <div className="block">
          <span className="label">Контроль:</span>
          <span className={`value integrity-${status.controlIntegrity}`}>
            {
              status.controlIntegrity === 'verified'
                ? 'Подтверждён'
                : status.controlIntegrity === 'uncertain'
                ? 'Неопределён'
                : 'Скомпрометирован'
            }
          </span>
        </div>
      </div>

      {status.controlIntegrity === 'compromised' && (
        <Alert
          type="error"
          title="Угроза управления"
          message="Связь с наставником агента скомпрометирована. Автоматические меры предприняты."
        />
      )}
    </div>
  );
};
