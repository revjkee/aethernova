/**
 * XAI Widget Export Index
 * © TeslaAI Genesis — NeuroCity 2025
 * Автоматически управляет экспортом всех XAI-компонентов.
 * Обеспечивает: безопасность, масштабируемость, контроль, трассировку и сборку.
 */

import type { ComponentType } from 'react'

/**
 * Явные импорты (статичные для критически важных компонентов)
 */
export { default as WidgetLoader } from './WidgetLoader'
export { default as XAIUserOverrideNotice } from './XAIUserOverrideNotice'
export { default as ExplanationExportPanel } from './ExplanationExportPanel'

/**
 * Динамические ленивые импорты через map-реестр
 */
export const XAIWidgetRegistry: Record<string, () => Promise<{ default: ComponentType<any> }>> = {
  AgentCausalChain: () => import('./AgentCausalChain'),
  AgentBiasInspector: () => import('./AgentBiasInspector'),
  ActionTransparencyBadge: () => import('./ActionTransparencyBadge'),
  ExplanationDeltaViewer: () => import('./ExplanationDeltaViewer'),
  ExplanationValidator: () => import('./ExplanationValidator'),
  ExplanationWatchlist: () => import('./ExplanationWatchlist'),
  ZKExplainVerifier: () => import('./ZKExplainVerifier'),
  LayerActivationPlot: () => import('./LayerActivationPlot'),
  MultimodalExplanationCombiner: () => import('./MultimodalExplanationCombiner'),
  CausalImpactMeter: () => import('./CausalImpactMeter'),
  TransparentPolicyRenderer: () => import('./TransparentPolicyRenderer'),
  TraceabilityChainViewer: () => import('./TraceabilityChainViewer'),
  RealTimeExplanationFeed: () => import('./RealTimeExplanationFeed'),
  ExplainabilityComplianceTag: () => import('./ExplainabilityComplianceTag'),
  XAIIntentComparator: () => import('./XAIIntentComparator'),
  DecisionHighlightMap: () => import('./DecisionHighlightMap'),
  XAISandboxSimulator: () => import('./XAISandboxSimulator'),
  InfluenceGraphViewer: () => import('./InfluenceGraphViewer')
}

/**
 * Экспорт идентификаторов доступных виджетов
 */
export const XAIWidgetKeys = Object.keys(XAIWidgetRegistry) as Array<keyof typeof XAIWidgetRegistry>

/**
 * Получение компонента XAI по идентификатору
 */
export async function loadXAIWidgetByKey(
  key: keyof typeof XAIWidgetRegistry
): Promise<ComponentType<any>> {
  const loader = XAIWidgetRegistry[key]
  if (!loader) {
    throw new Error(`[XAI] Виджет с ключом "${key}" не найден в реестре.`)
  }
  const mod = await loader()
  return mod.default
}

/**
 * Проверка существования ключа (для guard)
 */
export function isValidXAIWidget(key: string): key is keyof typeof XAIWidgetRegistry {
  return key in XAIWidgetRegistry
}
