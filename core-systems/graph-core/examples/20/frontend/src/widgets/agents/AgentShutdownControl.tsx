import React, { useState } from 'react';
import { useMutation } from '@/shared/hooks/useMutation';
import { ConfirmDialog } from '@/shared/components/modals/ConfirmDialog';
import { Button } from '@/shared/components/Button';
import { Dropdown } from '@/shared/components/Dropdown';
import { Tooltip } from '@/shared/components/Tooltip';
import { AgentShieldIcon } from '@/shared/components/icons/AgentShieldIcon';
import { toast } from '@/shared/utils/toast';
import './styles/AgentShutdownControl.css';

interface AgentShutdownControlProps {
  agentId: string;
  currentStatus: 'active' | 'idle' | 'sandboxed' | 'locked';
  onUpdate?: () => void;
}

const ACTIONS = [
  { label: 'Заморозить (Freeze)', value: 'freeze' },
  { label: 'Отключить (Shutdown)', value: 'shutdown' },
  { label: 'Заблокировать (Jail)', value: 'jail' },
];

export const AgentShutdownControl: React.FC<AgentShutdownControlProps> = ({
  agentId,
  currentStatus,
  onUpdate,
}) => {
  const [selectedAction, setSelectedAction] = useState<string | null>(null);
  const [isDialogOpen, setIsDialogOpen] = useState(false);

  const { mutateAsync: triggerControl, loading } = useMutation(`/agents/${agentId}/control`, {
    method: 'POST',
  });

  const handleConfirm = async () => {
    if (!selectedAction) return;

    try {
      await triggerControl({
        action: selectedAction,
        timestamp: Date.now(),
        operator: 'UI_OPERATOR',
        reason: 'Manual intervention via shutdown control widget',
      });

      toast.success(`Агент ${agentId} успешно: ${selectedAction}`);
      onUpdate?.();
    } catch (error) {
      toast.error(`Ошибка управления агентом: ${String(error)}`);
    } finally {
      setIsDialogOpen(false);
      setSelectedAction(null);
    }
  };

  const handleAction = (action: string) => {
    setSelectedAction(action);
    setIsDialogOpen(true);
  };

  const renderButtonLabel = () => {
    switch (currentStatus) {
      case 'active':
        return 'Отключить';
      case 'idle':
        return 'Команды';
      case 'sandboxed':
        return 'Снять изоляцию';
      case 'locked':
        return 'Заблокирован';
      default:
        return 'Управление';
    }
  };

  return (
    <div className="agent-shutdown-control">
      <Tooltip content="Управление режимами агента (Zero Trust)">
        <Dropdown
          icon={<AgentShieldIcon size={18} />}
          label={renderButtonLabel()}
          disabled={currentStatus === 'locked'}
          options={ACTIONS}
          onSelect={handleAction}
          className="shutdown-dropdown"
        />
      </Tooltip>

      {isDialogOpen && (
        <ConfirmDialog
          title="Подтвердите действие"
          message={`Вы уверены, что хотите выполнить "${selectedAction}" для агента ${agentId}? Это действие будет зафиксировано в журналах исполнения.`}
          onConfirm={handleConfirm}
          onCancel={() => setIsDialogOpen(false)}
          loading={loading}
          danger
        />
      )}
    </div>
  );
};
