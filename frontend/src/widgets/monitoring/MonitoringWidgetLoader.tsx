// src/widgets/Monitoring/MonitoringWidgetLoader.tsx

import React, {
  lazy,
  Suspense,
  useEffect,
  useState,
  useMemo,
  useCallback,
  FC,
} from 'react';
import { Loader } from '@/components/ui/Loader';
import { ErrorBoundary } from '@/shared/components/ErrorBoundary';
import { useMonitoringContext } from '@/shared/hooks/useMonitoringContext';
import { useTelemetry } from '@/shared/hooks/useTelemetry';
import { cn } from '@/shared/utils/classNames';
import { trackWidgetLoad } from '@/shared/utils/telemetry';
import { toast } from '@/components/ui/toast';

const IncidentTimeline = lazy(() => import('./IncidentTimeline'));
const MetricReplaySlider = lazy(() => import('./MetricReplaySlider'));
const SystemHealthOverview = lazy(() => import('./SystemHealthOverview'));
const AlertFeed = lazy(() => import('./AlertFeed'));
const MetricsPanel = lazy(() => import('./MetricsPanel'));
const CorrelationGraph = lazy(() => import('./CorrelationGraph'));
const PredictiveFailuresPanel = lazy(() => import('./PredictiveFailuresPanel'));
const ThreatHorizonMap = lazy(() => import('./ThreatHorizonMap'));

const COMPONENT_MAP = {
  timeline: IncidentTimeline,
  slider: MetricReplaySlider,
  health: SystemHealthOverview,
  alerts: AlertFeed,
  metrics: MetricsPanel,
  correlation: CorrelationGraph,
  predictive: PredictiveFailuresPanel,
  threats: ThreatHorizonMap,
} as const;

type ComponentKey = keyof typeof COMPONENT_MAP;

interface MonitoringWidgetLoaderProps {
  widgets: ComponentKey[];
  layout?: 'grid' | 'flex' | 'stacked';
  className?: string;
}

export const MonitoringWidgetLoader: FC<MonitoringWidgetLoaderProps> = ({
  widgets,
  layout = 'grid',
  className,
}) => {
  const { preferences } = useMonitoringContext();
  const telemetry = useTelemetry();
  const [loadedComponents, setLoadedComponents] = useState<Record<string, boolean>>({});

  const layoutClass = useMemo(() => {
    switch (layout) {
      case 'grid':
        return 'grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4';
      case 'flex':
        return 'flex flex-wrap gap-4';
      case 'stacked':
        return 'flex flex-col gap-4';
      default:
        return '';
    }
  }, [layout]);

  const onComponentLoad = useCallback(
    (key: ComponentKey) => {
      telemetry.send(trackWidgetLoad(key));
      setLoadedComponents((prev) => ({ ...prev, [key]: true }));
    },
    [telemetry]
  );

  const handleLoadError = useCallback((key: ComponentKey, error: Error) => {
    toast({
      title: `Ошибка загрузки: ${key}`,
      description: error.message,
      variant: 'destructive',
    });
  }, []);

  useEffect(() => {
    widgets.forEach((key) => {
      if (!COMPONENT_MAP[key]) {
        console.warn(`[MonitoringWidgetLoader] Неизвестный ключ компонента: ${key}`);
      }
    });
  }, [widgets]);

  return (
    <div className={cn('monitoring-loader-container', layoutClass, className)}>
      {widgets.map((key) => {
        const Component = COMPONENT_MAP[key];
        if (!Component) return null;

        return (
          <ErrorBoundary
            key={key}
            fallback={
              <div className="p-4 border border-destructive bg-destructive/10 text-destructive rounded">
                Ошибка при загрузке компонента: {key}
              </div>
            }
            onError={(error) => handleLoadError(key, error)}
          >
            <Suspense
              fallback={<Loader className="w-full h-32 rounded bg-muted animate-pulse" />}
            >
              <Component
                onLoad={() => onComponentLoad(key)}
                preferences={preferences}
              />
            </Suspense>
          </ErrorBoundary>
        );
      })}
    </div>
  );
};
