// Централизованный промышленный экспорт всех HR-виджетов
// Модуль полностью совместим с: TypeScript, ESM, Vite/Rollup, auto-intellisense и dynamic-import'ами

// Candidate
export { CandidateProfileCard } from "./CandidateProfileCard";
export { CompetencyMatrixChart } from "./CompetencyMatrixChart";
export { TeamInsightsWidget } from "./TeamInsightsWidget";
export { AIInterviewFeedback } from "./AIInterviewFeedback";
export { ApplicantTimelineView } from "./ApplicantTimelineView";
export { PersonalityDiagnosticsPanel } from "./PersonalityDiagnosticsPanel";
export { SkillRadarGraph } from "./SkillRadarGraph";
export { CandidateRankIndicator } from "./CandidateRankIndicator";
export { RoleFitPredictor } from "./RoleFitPredictor";
export { EthicsCompatibilityView } from "./EthicsCompatibilityView";

// HR Process
export { HRQuickActionsPanel } from "./HRQuickActionsPanel";
export { HRReviewCommentBox } from "./HRReviewCommentBox";
export { HRKPIWidget } from "./HRKPIWidget";
export { OnboardingReadiness } from "./OnboardingReadiness";
export { ReferralInfoTag } from "./ReferralInfoTag";
export { SalaryRangeVisualizer } from "./SalaryRangeVisualizer";
export { CultureMatchWidget } from "./CultureMatchWidget";

// Compliance & Security
export { BackgroundCheckStatus } from "./BackgroundCheckStatus";
export { PolicyComplianceIndicator } from "./PolicyComplianceIndicator";
export { HRPrivacyStatusBadge } from "./HRPrivacyStatusBadge";
export { AccessClearanceLevelView } from "./AccessClearanceLevelView";
export { AnomalyFlagMarker } from "./AnomalyFlagMarker";

// AI + Agent
export { AgentAssignmentWidget } from "./AgentAssignmentWidget";

// System
export { WidgetLoader } from "./WidgetLoader";

// Для AI-интерфейса и автодокументации
export const HR_WIDGET_LIST = [
  "CandidateProfileCard",
  "CompetencyMatrixChart",
  "TeamInsightsWidget",
  "AIInterviewFeedback",
  "ApplicantTimelineView",
  "PersonalityDiagnosticsPanel",
  "SkillRadarGraph",
  "CandidateRankIndicator",
  "RoleFitPredictor",
  "EthicsCompatibilityView",
  "HRQuickActionsPanel",
  "HRReviewCommentBox",
  "HRKPIWidget",
  "OnboardingReadiness",
  "ReferralInfoTag",
  "SalaryRangeVisualizer",
  "CultureMatchWidget",
  "BackgroundCheckStatus",
  "PolicyComplianceIndicator",
  "HRPrivacyStatusBadge",
  "AccessClearanceLevelView",
  "AnomalyFlagMarker",
  "AgentAssignmentWidget",
  "WidgetLoader"
] as const;

export type HRWidgetName = typeof HR_WIDGET_LIST[number];
