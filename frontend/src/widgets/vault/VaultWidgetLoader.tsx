import React, { Suspense, lazy, useEffect, useState, useMemo } from 'react';
import { Spinner } from '@/shared/components/Spinner';
import { ErrorBoundary } from '@/shared/components/ErrorBoundary';
import { useRBAC } from '@/shared/hooks/useRBAC';
import { useLatencyTracker } from '@/logging/latency/latency_tracker';
import { logAction } from '@/services/logging/auditLogger';
import { useTheme } from '@/shared/hooks/useTheme';
import { Alert } from '@/shared/components/Alert';

interface VaultWidgetLoaderProps {
  widget: 'SnapshotComparator' | 'AnomalyDetector' | 'BackupManager' | 'ZeroAccessViewer' | 'KeySharingLinkModal';
  objectId: string;
  userId?: string;
  fallbackHeight?: number;
}

const WIDGET_MAP = {
  SnapshotComparator: lazy(() => import('./VaultSnapshotComparator')),
  AnomalyDetector: lazy(() => import('./VaultAnomalyDetector')),
  BackupManager: lazy(() => import('./VaultBackupManager')),
  ZeroAccessViewer: lazy(() => import('./VaultZeroAccessViewer')),
  KeySharingLinkModal: lazy(() => import('./KeySharingLinkModal')),
} as const;

const PERMISSIONS_MAP: Record<VaultWidgetLoaderProps['widget'], string> = {
  SnapshotComparator: 'vault.snapshot.compare',
  AnomalyDetector: 'vault.anomaly.view',
  BackupManager: 'vault.backup.manage',
  ZeroAccessViewer: 'vault.access.zero.view',
  KeySharingLinkModal: 'vault.key.sharing',
};

export const VaultWidgetLoader: React.FC<VaultWidgetLoaderProps> = ({
  widget,
  objectId,
  userId = 'unknown',
  fallbackHeight = 300,
}) => {
  const { hasPermission } = useRBAC();
  const { trackLatency } = useLatencyTracker();
  const { theme } = useTheme();

  const [allowed, setAllowed] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const LazyComponent = useMemo(() => WIDGET_MAP[widget], [widget]);

  useEffect(() => {
    const permissionKey = PERMISSIONS_MAP[widget];
    if (hasPermission(permissionKey)) {
      setAllowed(true);
      trackLatency(`vault_widget_${widget.toLowerCase()}`);
      logAction('vault_widget_loaded', {
        widget,
        objectId,
        userId,
        theme,
        timestamp: new Date().toISOString(),
      });
    } else {
      setAllowed(false);
      setError('Access Denied: Insufficient Permissions');
    }
  }, [widget, objectId, userId, hasPermission, trackLatency, theme]);

  if (!allowed) {
    return (
      <div className="p-4 border border-red-300 dark:border-red-700 bg-red-50 dark:bg-red-900 rounded-md">
        <Alert type="error" message={error || 'Unauthorized'} />
      </div>
    );
  }

  return (
    <div style={{ minHeight: fallbackHeight }}>
      <ErrorBoundary
        fallback={
          <Alert
            type="error"
            message={`Failed to load widget: ${widget}`}
          />
        }
      >
        <Suspense fallback={<Spinner label={`Loading ${widget}...`} />}>
          <LazyComponent objectId={objectId} userId={userId} />
        </Suspense>
      </ErrorBoundary>
    </div>
  );
};

export default VaultWidgetLoader;
