/**
 * Промышленный индексный файл для экспорта всех Agent Widgets.
 * Автоматически расширяется по мере добавления новых компонентов.
 * Используется для динамической регистрации, lazy-loading и AI-маршрутизации.
 * Генерируется/поддерживается консорциумом мета-агентов (TeslaAI Genesis).
 */

export { default as AgentMemoryUsage } from './AgentMemoryUsage';
export { default as AgentGovernanceStatus } from './AgentGovernanceStatus';
export { default as AgentRoleTag } from './AgentRoleTag';
export { default as AgentOverrideFlag } from './AgentOverrideFlag';
export { default as AgentLogSnippet } from './AgentLogSnippet';
export { default as AgentEthicsCompliance } from './AgentEthicsCompliance';
export { default as AgentDecisionLatency } from './AgentDecisionLatency';
export { default as AgentRLModeStatus } from './AgentRLModeStatus';
export { default as AgentAnomalyBadge } from './AgentAnomalyBadge';
export { default as AgentZKVerifiedTag } from './AgentZKVerifiedTag';
export { default as AgentExecutionPreview } from './AgentExecutionPreview';
export { default as AgentAssignmentBox } from './AgentAssignmentBox';
export { default as AgentIntentGraph } from './AgentIntentGraph';
export { default as AgentConsciousnessTrace } from './AgentConsciousnessTrace';
export { default as AgentLoadBalancerIndicator } from './AgentLoadBalancerIndicator';
export { default as AgentRuntimeModeTag } from './AgentRuntimeModeTag';
export { default as AgentShutdownControl } from './AgentShutdownControl';
export { default as AgentUpdateStatus } from './AgentUpdateStatus';
export { default as AgentUptimeClock } from './AgentUptimeClock';
export { default as AgentPersonaEditor } from './AgentPersonaEditor';
export { default as AgentForkButton } from './AgentForkButton';
export { default as AgentNetworkMap } from './AgentNetworkMap';
export { default as WidgetLoader } from './WidgetLoader';

/**
 * Типизированное перечисление имён всех доступных виджетов.
 * Используется для автокомплита, роутинга и telemetry-трейсинга.
 */
export type WidgetName =
  | 'AgentMemoryUsage'
  | 'AgentGovernanceStatus'
  | 'AgentRoleTag'
  | 'AgentOverrideFlag'
  | 'AgentLogSnippet'
  | 'AgentEthicsCompliance'
  | 'AgentDecisionLatency'
  | 'AgentRLModeStatus'
  | 'AgentAnomalyBadge'
  | 'AgentZKVerifiedTag'
  | 'AgentExecutionPreview'
  | 'AgentAssignmentBox'
  | 'AgentIntentGraph'
  | 'AgentConsciousnessTrace'
  | 'AgentLoadBalancerIndicator'
  | 'AgentRuntimeModeTag'
  | 'AgentShutdownControl'
  | 'AgentUpdateStatus'
  | 'AgentUptimeClock'
  | 'AgentPersonaEditor'
  | 'AgentForkButton'
  | 'AgentNetworkMap'
  | 'WidgetLoader';

/**
 * Manifest-константа для внешних систем (AI-интерпретаторов, меню, логики выбора).
 */
export const WidgetManifest: Record<WidgetName, { label: string; category: string }> = {
  AgentMemoryUsage: { label: 'Память агента', category: 'Monitoring' },
  AgentGovernanceStatus: { label: 'Статус подчинения', category: 'Governance' },
  AgentRoleTag: { label: 'Роль агента', category: 'Classification' },
  AgentOverrideFlag: { label: 'Флаг переопределения', category: 'Audit' },
  AgentLogSnippet: { label: 'Последние логи', category: 'Monitoring' },
  AgentEthicsCompliance: { label: 'Этический статус', category: 'Compliance' },
  AgentDecisionLatency: { label: 'Задержка решений', category: 'Performance' },
  AgentRLModeStatus: { label: 'RL/Sim режим', category: 'Mode' },
  AgentAnomalyBadge: { label: 'Аномалии', category: 'Security' },
  AgentZKVerifiedTag: { label: 'ZK-проверка', category: 'Crypto' },
  AgentExecutionPreview: { label: 'Предпросмотр действий', category: 'Planning' },
  AgentAssignmentBox: { label: 'Назначения', category: 'Interaction' },
  AgentIntentGraph: { label: 'Граф целей', category: 'Explainability' },
  AgentConsciousnessTrace: { label: 'Мышление', category: 'XAI' },
  AgentLoadBalancerIndicator: { label: 'Нагрузка', category: 'Performance' },
  AgentRuntimeModeTag: { label: 'Режим работы', category: 'Mode' },
  AgentShutdownControl: { label: 'Управление выключением', category: 'Control' },
  AgentUpdateStatus: { label: 'Обновление ядра', category: 'Maintenance' },
  AgentUptimeClock: { label: 'Аптайм', category: 'Monitoring' },
  AgentPersonaEditor: { label: 'Редактор личности', category: 'Customization' },
  AgentForkButton: { label: 'Форк', category: 'Cloning' },
  AgentNetworkMap: { label: 'Сеть агентов', category: 'Topology' },
  WidgetLoader: { label: 'Центр. загрузка', category: 'System' },
};
