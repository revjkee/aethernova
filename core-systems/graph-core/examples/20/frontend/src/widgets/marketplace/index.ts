/**
 * Centralized re-exports for all Marketplace widgets.
 * Optimized for tree-shaking, static analysis, CI linting and microbundle orchestration.
 * All exports are grouped and categorized by functional domains.
 * Every component is auto-wired into devtools and introspection registry.
 */

export * from "./CheckoutFlow"
export * from "./MarketplaceAdminPanel"
export * from "./MarketplaceCard"
export * from "./MarketplaceDebugPanel"
export * from "./MarketplaceFilterPanel"
export * from "./MarketplaceGridView"
export * from "./MarketplaceItemEditor"
export * from "./MarketplaceOnboardingTour"
export * from "./MarketplacePagination"
export * from "./MarketplaceSubscriptionBadge"
export * from "./ProductOwnershipBadge"
export * from "./ProductCategorySelector"
export * from "./OnchainOfferLink"
export * from "./TokenPaymentButton"
export * from "./ProductListInspector"

// Selectors
export * from "./selectors/useMarketplaceConfig"
export * from "./selectors/useMarketplaceMetadata"

// DevOps & Telemetry Utilities
export * from "./telemetry/MarketplaceHealthPing"
export * from "./telemetry/useMarketplaceSyncStatus"

// ZK / Web3 Auth
export * from "./zk/useVerifyNFTAccess"
export * from "./zk/MarketplaceZKProofViewer"

// Fallbacks
export * from "./fallback/MarketplaceEmptyState"
export * from "./fallback/MarketplaceErrorBoundary"

// Internal Bus
export * from "./debug/InternalBusMonitor"

// Global Init Injection
export * from "./__bootstrap__/MarketplaceWidgetRegistry"

// Type Declarations
export type {
  MarketplaceWidgetProps,
  MarketplaceProductMeta,
  SubscriptionTier,
  TokenPaymentEvent,
  OnchainLinkProps
} from "./types"

// Manifest (used for runtime inspection / sandbox orchestration / CI coverage maps)
export { MarketplaceManifest } from "./manifest"

// Integration ID (constant per build)
export const MARKETPLACE_WIDGETS_VERSION = "v4.8.20-genesis-final"
export const MARKETPLACE_INTEGRATION_KEY = "NEUROCITY::MARKETPLACE::WIDGETS"

