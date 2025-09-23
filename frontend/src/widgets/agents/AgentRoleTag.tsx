import React from 'react';
import './styles/AgentRoleTag.css';
import { RoleIcon } from '@/shared/components/icons/RoleIcon';
import { Tooltip } from '@/shared/components/Tooltip';

export type AgentRole =
  | 'observer'
  | 'planner'
  | 'executor'
  | 'critic'
  | 'coordinator'
  | 'learner'
  | 'analyzer'
  | 'negotiator'
  | 'security'
  | 'autonomous'
  | 'governor'
  | 'external';

interface AgentRoleTagProps {
  role: AgentRole;
  size?: 'small' | 'medium' | 'large';
  withTooltip?: boolean;
  isActive?: boolean;
  isCritical?: boolean;
}

const ROLE_LABELS: Record<AgentRole, string> = {
  observer: 'Наблюдатель',
  planner: 'Планировщик',
  executor: 'Исполнитель',
  critic: 'Критик',
  coordinator: 'Координатор',
  learner: 'Обучающийся',
  analyzer: 'Аналитик',
  negotiator: 'Переговорщик',
  security: 'Безопасность',
  autonomous: 'Автономный',
  governor: 'Губернатор',
  external: 'Внешний агент',
};

const ROLE_COLORS: Record<AgentRole, string> = {
  observer: '#9e9e9e',
  planner: '#42a5f5',
  executor: '#66bb6a',
  critic: '#ef5350',
  coordinator: '#ab47bc',
  learner: '#ffb74d',
  analyzer: '#26c6da',
  negotiator: '#8d6e63',
  security: '#f44336',
  autonomous: '#607d8b',
  governor: '#d4af37',
  external: '#bdbdbd',
};

export const AgentRoleTag: React.FC<AgentRoleTagProps> = ({
  role,
  size = 'medium',
  withTooltip = true,
  isActive = true,
  isCritical = false,
}) => {
  const label = ROLE_LABELS[role];
  const color = ROLE_COLORS[role];

  const classNames = [
    'agent-role-tag',
    size,
    isActive ? 'active' : 'inactive',
    isCritical ? 'critical' : '',
  ].join(' ');

  const tagContent = (
    <span
      className={classNames}
      style={{
        borderColor: color,
        color: isCritical ? '#fff' : color,
        backgroundColor: isCritical ? color : 'transparent',
      }}
    >
      <RoleIcon role={role} color={color} />
      <span className="label">{label}</span>
    </span>
  );

  return withTooltip ? (
    <Tooltip content={`Роль агента: ${label}`}>
      {tagContent}
    </Tooltip>
  ) : (
    tagContent
  );
};
