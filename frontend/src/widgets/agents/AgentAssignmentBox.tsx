import React, { useEffect, useState } from 'react';
import { fetchAvailableAgents, assignAgentToTarget } from '@/services/agentAssignmentService';
import { useTheme } from '@/shared/hooks/useThemeSwitcher';
import { Dropdown } from '@/shared/components/Dropdown';
import { Button } from '@/shared/components/Button';
import { Tooltip } from '@/shared/components/Tooltip';
import { Spinner } from '@/shared/components/Spinner';
import './styles/AgentAssignmentBox.css';

interface AgentProfile {
  id: string;
  name: string;
  role: string;
  availability: 'available' | 'busy' | 'offline';
  skillScore: number;
  avatarUrl?: string;
}

interface AgentAssignmentBoxProps {
  targetId: string;
  targetType: 'task' | 'user' | 'case';
  preselectAgentId?: string;
  readOnly?: boolean;
  onAssign?: (agent: AgentProfile) => void;
}

export const AgentAssignmentBox: React.FC<AgentAssignmentBoxProps> = ({
  targetId,
  targetType,
  preselectAgentId,
  readOnly = false,
  onAssign,
}) => {
  const { theme } = useTheme();
  const [agents, setAgents] = useState<AgentProfile[]>([]);
  const [selectedAgent, setSelectedAgent] = useState<string | null>(preselectAgentId || null);
  const [loading, setLoading] = useState(true);
  const [assigning, setAssigning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchAvailableAgents()
      .then((res) => {
        setAgents(res);
        setLoading(false);
      })
      .catch(() => {
        setError('Ошибка загрузки агентов');
        setLoading(false);
      });
  }, []);

  const handleAssign = async () => {
    if (!selectedAgent) return;
    setAssigning(true);
    try {
      const agent = agents.find((a) => a.id === selectedAgent)!;
      await assignAgentToTarget(selectedAgent, targetId, targetType);
      onAssign?.(agent);
    } catch (e) {
      setError('Не удалось назначить агента');
    } finally {
      setAssigning(false);
    }
  };

  const getAgentLabel = (agent: AgentProfile) =>
    `${agent.name} — ${agent.role} (${agent.skillScore}%)`;

  const getStatusColor = (status: AgentProfile['availability']) => {
    switch (status) {
      case 'available':
        return 'status-green';
      case 'busy':
        return 'status-orange';
      case 'offline':
        return 'status-gray';
    }
  };

  if (loading) {
    return <div className="assignment-box loading"><Spinner /></div>;
  }

  return (
    <div className={`assignment-box ${theme}`}>
      <div className="assignment-label">Назначить агента:</div>
      {error && <div className="assignment-error">{error}</div>}
      <Dropdown
        disabled={readOnly}
        options={agents.map((agent) => ({
          label: getAgentLabel(agent),
          value: agent.id,
          icon: (
            <div className={`status-dot ${getStatusColor(agent.availability)}`} />
          ),
        }))}
        value={selectedAgent}
        onChange={(val) => setSelectedAgent(val)}
        placeholder="Выберите агента"
      />
      {!readOnly && (
        <Tooltip content="Назначить выбранного агента">
          <Button
            disabled={!selectedAgent || assigning}
            loading={assigning}
            onClick={handleAssign}
            size="small"
            className="assign-button"
          >
            Назначить
          </Button>
        </Tooltip>
      )}
    </div>
  );
};
