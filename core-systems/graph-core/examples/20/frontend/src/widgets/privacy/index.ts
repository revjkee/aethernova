// CENTRALIZED EXPORT FOR PRIVACY WIDGETS (INDUSTRIAL-GRADE)
// TeslaAI Genesis / NeuroCity Platform
// Version: AI-Enhanced Modular UI v3.2

// --- Lazy Imports (Code Splitting Support) ---
export const LazyAIPrivacyScoreGraph = async () =>
  (await import("./AIPrivacyScoreGraph")).AIPrivacyScoreGraph;

export const LazyPrivacyAlertBanner = async () =>
  (await import("./PrivacyAlertBanner")).PrivacyAlertBanner;

export const LazyPrivacyTrustPanel = async () =>
  (await import("./PrivacyTrustPanel")).PrivacyTrustPanel;

export const LazyAnonLevelIndicator = async () =>
  (await import("./AnonLevelIndicator")).AnonLevelIndicator;

export const LazyDataAccessHeatmap = async () =>
  (await import("./DataAccessHeatmap")).DataAccessHeatmap;

export const LazyZKComplianceGauge = async () =>
  (await import("./ZKComplianceGauge")).ZKComplianceGauge;

export const LazyPrivacyIncidentTimeline = async () =>
  (await import("./PrivacyIncidentTimeline")).PrivacyIncidentTimeline;

export const LazyAIPrivacyAnalysisTable = async () =>
  (await import("./AIPrivacyAnalysisTable")).AIPrivacyAnalysisTable;

export const LazySecureNetworkFlow = async () =>
  (await import("./SecureNetworkFlow")).SecureNetworkFlow;

// --- Named Static Exports (for SSR/Tests/Direct Use) ---
export { AIPrivacyScoreGraph } from "./AIPrivacyScoreGraph";
export { PrivacyAlertBanner } from "./PrivacyAlertBanner";
export { PrivacyTrustPanel } from "./PrivacyTrustPanel";
export { AnonLevelIndicator } from "./AnonLevelIndicator";
export { DataAccessHeatmap } from "./DataAccessHeatmap";
export { ZKComplianceGauge } from "./ZKComplianceGauge";
export { PrivacyIncidentTimeline } from "./PrivacyIncidentTimeline";
export { AIPrivacyAnalysisTable } from "./AIPrivacyAnalysisTable";
export { SecureNetworkFlow } from "./SecureNetworkFlow";

// --- Metadata Registry (for Dynamic UI Composition Engines) ---
export const privacyWidgetRegistry = {
  AIPrivacyScoreGraph: {
    component: LazyAIPrivacyScoreGraph,
    title: "AI Privacy Risk Graph",
    description: "Отображает уровень угроз приватности по ИИ-оценке",
    tags: ["graph", "risk", "AI", "privacy"],
  },
  PrivacyAlertBanner: {
    component: LazyPrivacyAlertBanner,
    title: "Privacy Warning",
    description: "Визуальное оповещение о критических инцидентах",
    tags: ["alert", "privacy", "warning"],
  },
  PrivacyTrustPanel: {
    component: LazyPrivacyTrustPanel,
    title: "Trust Score Panel",
    description: "Аналитика доверия пользователей по слоям модели",
    tags: ["trust", "score", "panel"],
  },
  AnonLevelIndicator: {
    component: LazyAnonLevelIndicator,
    title: "Anonymity Level",
    description: "Индикация текущего уровня анонимности",
    tags: ["anon", "indicator", "privacy"],
  },
  DataAccessHeatmap: {
    component: LazyDataAccessHeatmap,
    title: "Access Heatmap",
    description: "Карта доступа к данным по зонам и времени",
    tags: ["heatmap", "data access"],
  },
  ZKComplianceGauge: {
    component: LazyZKComplianceGauge,
    title: "ZK Compliance Level",
    description: "График соответствия ZK-приватности",
    tags: ["zk", "compliance", "gauge"],
  },
  PrivacyIncidentTimeline: {
    component: LazyPrivacyIncidentTimeline,
    title: "Privacy Incidents",
    description: "Хронология утечек, вторжений и вмешательств",
    tags: ["timeline", "incident", "privacy"],
  },
  AIPrivacyAnalysisTable: {
    component: LazyAIPrivacyAnalysisTable,
    title: "Privacy Analysis Table",
    description: "AI-анализ метрик рисков приватности",
    tags: ["table", "analysis", "privacy"],
  },
  SecureNetworkFlow: {
    component: LazySecureNetworkFlow,
    title: "Secure Network Flow",
    description: "Диаграмма защищённого потока данных",
    tags: ["network", "flow", "secure"],
  },
};

// --- Industrial Tag Export (meta-dependents, logging systems) ---
export const PRIVACY_WIDGET_TAGS = [
  "privacy",
  "trust",
  "anon",
  "zk",
  "compliance",
  "risk",
  "secure-network",
  "timeline",
  "heatmap",
];

// --- Type Definitions ---
export type PrivacyWidgetKey = keyof typeof privacyWidgetRegistry;

export interface PrivacyWidgetMeta {
  component: () => Promise<React.FC>;
  title: string;
  description: string;
  tags: string[];
}
