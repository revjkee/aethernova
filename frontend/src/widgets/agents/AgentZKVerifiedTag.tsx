import React, { useEffect, useState } from 'react';
import { useSocket } from '@/shared/hooks/useSocket';
import { useTheme } from '@/shared/hooks/useThemeSwitcher';
import { Tooltip } from '@/shared/components/Tooltip';
import { Spinner } from '@/shared/components/Spinner';
import { ZKProofIcon } from '@/shared/components/icons/ZKProofIcon';
import './styles/AgentZKVerifiedTag.css';

type ZKStatus = 'pending' | 'verified' | 'invalid' | 'expired';

interface ZKProofData {
  proofId: string;
  agentId: string;
  timestamp: number;
  status: ZKStatus;
  proofType: 'zk-snark' | 'zk-stark' | 'zk-sigma' | 'zk-bulletproof';
  issuedBy: string;
  expiry: number;
}

interface AgentZKVerifiedTagProps {
  agentId: string;
  compact?: boolean;
}

export const AgentZKVerifiedTag: React.FC<AgentZKVerifiedTagProps> = ({ agentId, compact = false }) => {
  const [zkData, setZkData] = useState<ZKProofData | null>(null);
  const [loading, setLoading] = useState(true);
  const { theme } = useTheme();
  const { connect, disconnect } = useSocket(`/agents/${agentId}/zk_proof`);

  useEffect(() => {
    const socket = connect((event) => {
      const data: ZKProofData = JSON.parse(event.data);
      setZkData(data);
      setLoading(false);
    });
    return () => disconnect(socket);
  }, [agentId]);

  if (loading || !zkData) {
    return (
      <div className="zk-tag loading">
        <Spinner size="small" />
      </div>
    );
  }

  const statusClass = `zk-${zkData.status}`;
  const expiryDate = new Date(zkData.expiry).toLocaleString('ru-RU');
  const issuedAt = new Date(zkData.timestamp).toLocaleString('ru-RU');

  const label = zkData.status === 'verified'
    ? 'ZK-подтверждён'
    : zkData.status === 'expired'
    ? 'ZK-истёк'
    : zkData.status === 'invalid'
    ? 'ZK-недействителен'
    : 'ZK-ожидание';

  const iconVariant = compact ? 'small' : 'default';

  return (
    <Tooltip
      content={
        <div className="zk-tooltip">
          <div><strong>Тип доказательства:</strong> {zkData.proofType.toUpperCase()}</div>
          <div><strong>Выдано:</strong> {zkData.issuedBy}</div>
          <div><strong>Состояние:</strong> {label}</div>
          <div><strong>Создано:</strong> {issuedAt}</div>
          <div><strong>Истекает:</strong> {expiryDate}</div>
        </div>
      }
    >
      <div className={`zk-tag ${statusClass} ${theme} ${compact ? 'compact' : ''}`}>
        <ZKProofIcon variant={iconVariant} />
        {!compact && <span className="zk-label">{label}</span>}
      </div>
    </Tooltip>
  );
};
