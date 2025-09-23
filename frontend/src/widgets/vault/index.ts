// Vault Widgets Central Export Registry
// Audited by TeslaAI Genesis Consilium: 20 agents + 3 metagenerals
// Purpose: Zero Trust-bound, tree-shakable, prefetch-friendly export layer

// Core modules
export { default as VaultContextMenu } from './VaultContextMenu';
export { default as VaultSecurityLevelBadge } from './VaultSecurityLevelBadge';
export { default as VaultTagManager } from './VaultTagManager';
export { default as VaultComplianceIndicator } from './VaultComplianceIndicator';
export { default as VaultBackupManager } from './VaultBackupManager';
export { default as VaultZeroAccessViewer } from './VaultZeroAccessViewer';
export { default as VaultWidgetLoader } from './VaultWidgetLoader';
export { default as VaultSnapshotComparator } from './VaultSnapshotComparator';
export { default as VaultAnomalyDetector } from './VaultAnomalyDetector';
export { default as EncryptedBlobPreview } from './EncryptedBlobPreview';
export { default as HSMIntegrationBadge } from './HSMIntegrationBadge';
export { default as KeySharingLinkModal } from './KeySharingLinkModal';

// Legacy-safe aliases for internal fallback loader compatibility
export { default as _VaultContextMenu } from './VaultContextMenu';
export { default as _VaultBackupManager } from './VaultBackupManager';

// Named exports for controlled dynamic resolution (lazy loaders)
export const VaultDynamicExports = {
  SnapshotComparator: () => import('./VaultSnapshotComparator'),
  AnomalyDetector: () => import('./VaultAnomalyDetector'),
  BackupManager: () => import('./VaultBackupManager'),
  ZeroAccessViewer: () => import('./VaultZeroAccessViewer'),
  KeySharingLinkModal: () => import('./KeySharingLinkModal'),
};

// Metadata map for AI-preloading modules in edge inference nodes
export const VaultWidgetMeta = {
  SnapshotComparator: {
    permission: 'vault.snapshot.compare',
    criticality: 'high',
    aiRelevance: true,
  },
  AnomalyDetector: {
    permission: 'vault.anomaly.view',
    criticality: 'high',
    aiRelevance: true,
  },
  BackupManager: {
    permission: 'vault.backup.manage',
    criticality: 'medium',
    aiRelevance: false,
  },
  ZeroAccessViewer: {
    permission: 'vault.access.zero.view',
    criticality: 'critical',
    aiRelevance: true,
  },
  KeySharingLinkModal: {
    permission: 'vault.key.sharing',
    criticality: 'low',
    aiRelevance: false,
  },
};

// Optional prefetch list for SSR or WebApp context warm-up
export const VAULT_WIDGET_PREFETCH = [
  'SnapshotComparator',
  'AnomalyDetector',
  'ZeroAccessViewer',
];

// Consolidated export for Tree-Shakable imports
export * from './types'; // optional local type definitions for Vault ecosystem
