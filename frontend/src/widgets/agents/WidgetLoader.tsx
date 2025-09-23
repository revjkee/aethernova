import React, { Suspense, useEffect, useState } from 'react';
import dynamic from 'next/dynamic';
import { WidgetName, WidgetManifest } from '@/shared/config/widget-manifest';
import { ErrorBoundary } from '@/shared/components/ErrorBoundary';
import { Spinner } from '@/shared/components/Spinner';
import { telemetry } from '@/shared/lib/telemetry';
import { useZeroTrust } from '@/shared/hooks/useZeroTrust';
import { useAgentContext } from '@/shared/context/AgentContext';

interface WidgetLoaderProps {
  widget: WidgetName;
  fallback?: React.ReactNode;
  priority?: number; // lower number = higher priority
  traceLabel?: string;
}

const widgetComponents: Record<WidgetName, () => Promise<any>> = {
  AgentMemoryUsage: () => import('./AgentMemoryUsage'),
  AgentGovernanceStatus: () => import('./AgentGovernanceStatus'),
  AgentRoleTag: () => import('./AgentRoleTag'),
  AgentOverrideFlag: () => import('./AgentOverrideFlag'),
  AgentLogSnippet: () => import('./AgentLogSnippet'),
  AgentEthicsCompliance: () => import('./AgentEthicsCompliance'),
  AgentDecisionLatency: () => import('./AgentDecisionLatency'),
  AgentRLModeStatus: () => import('./AgentRLModeStatus'),
  AgentAnomalyBadge: () => import('./AgentAnomalyBadge'),
  AgentZKVerifiedTag: () => import('./AgentZKVerifiedTag'),
  AgentExecutionPreview: () => import('./AgentExecutionPreview'),
  AgentAssignmentBox: () => import('./AgentAssignmentBox'),
  AgentIntentGraph: () => import('./AgentIntentGraph'),
  AgentConsciousnessTrace: () => import('./AgentConsciousnessTrace'),
  AgentLoadBalancerIndicator: () => import('./AgentLoadBalancerIndicator'),
  AgentRuntimeModeTag: () => import('./AgentRuntimeModeTag'),
  AgentShutdownControl: () => import('./AgentShutdownControl'),
  AgentUpdateStatus: () => import('./AgentUpdateStatus'),
  AgentUptimeClock: () => import('./AgentUptimeClock'),
  AgentPersonaEditor: () => import('./AgentPersonaEditor'),
  AgentForkButton: () => import('./AgentForkButton'),
  AgentNetworkMap: () => import('./AgentNetworkMap'),
};

export const WidgetLoader: React.FC<WidgetLoaderProps> = ({
  widget,
  fallback = <Spinner label={`Загрузка ${widget}`} />,
  priority = 10,
  traceLabel,
}) => {
  const [LazyWidget, setLazyWidget] = useState<React.ComponentType<any> | null>(null);
  const [timeoutExceeded, setTimeoutExceeded] = useState(false);
  const { agentId } = useAgentContext();
  const { allowRender } = useZeroTrust();

  useEffect(() => {
    let cancelled = false;
    let timeout = setTimeout(() => {
      if (!cancelled) setTimeoutExceeded(true);
    }, 8000); // 8 сек таймаут безопасной загрузки

    const traceId = telemetry.start(`widget-load:${widget}`, {
      priority,
      traceLabel: traceLabel || widget,
      agentId,
    });

    widgetComponents[widget]()
      .then((mod) => {
        if (!cancelled) {
          setLazyWidget(() => mod.default || mod[widget]);
        }
      })
      .catch((err) => {
        telemetry.error(`Widget load failure: ${widget}`, err);
      })
      .finally(() => {
        telemetry.end(traceId);
        clearTimeout(timeout);
      });

    return () => {
      cancelled = true;
      clearTimeout(timeout);
    };
  }, [widget]);

  if (timeoutExceeded) {
    return (
      <div className="text-sm text-red-500 p-2">
        Ошибка загрузки виджета <strong>{widget}</strong>. Попробуйте обновить страницу или проверьте лог сервера.
      </div>
    );
  }

  if (!LazyWidget || !allowRender(widget)) {
    return <>{fallback}</>;
  }

  return (
    <ErrorBoundary fallback={<div>Ошибка в компоненте {widget}</div>}>
      <Suspense fallback={fallback}>
        <LazyWidget />
      </Suspense>
    </ErrorBoundary>
  );
};
