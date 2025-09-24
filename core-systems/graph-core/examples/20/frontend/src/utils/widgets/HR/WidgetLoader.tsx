import { FC, Suspense, lazy, useMemo } from "react";
import { usePermission } from "@/shared/hooks/usePermission";
import { Role } from "@/shared/constants/roles";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorBoundary } from "react-error-boundary";
import { FallbackWidget } from "@/widgets/shared/FallbackWidget";
import { useHRWidgetConfig } from "@/widgets/HR/hooks/useHRWidgetConfig";
import { cn } from "@/lib/utils";
import { WidgetContainer } from "@/widgets/shared/WidgetContainer";

const widgetMap: Record<string, () => Promise<{ default: FC<any> }>> = {
  "CandidateProfileCard": () => import("./CandidateProfileCard"),
  "CompetencyMatrixChart": () => import("./CompetencyMatrixChart"),
  "TeamInsightsWidget": () => import("./TeamInsightsWidget"),
  "AIInterviewFeedback": () => import("./AIInterviewFeedback"),
  "HRQuickActionsPanel": () => import("./HRQuickActionsPanel"),
  "AgentAssignmentWidget": () => import("./AgentAssignmentWidget"),
  "SkillRadarGraph": () => import("./SkillRadarGraph"),
  "PersonalityDiagnosticsPanel": () => import("./PersonalityDiagnosticsPanel"),
  "ApplicantTimelineView": () => import("./ApplicantTimelineView"),
  "HRKPIWidget": () => import("./HRKPIWidget"),
  "BackgroundCheckStatus": () => import("./BackgroundCheckStatus"),
  "PolicyComplianceIndicator": () => import("./PolicyComplianceIndicator"),
  "HRPrivacyStatusBadge": () => import("./HRPrivacyStatusBadge"),
  "EthicsCompatibilityView": () => import("./EthicsCompatibilityView"),
  "SalaryRangeVisualizer": () => import("./SalaryRangeVisualizer"),
  "RoleFitPredictor": () => import("./RoleFitPredictor"),
  "CandidateRankIndicator": () => import("./CandidateRankIndicator"),
  "OnboardingReadiness": () => import("./OnboardingReadiness"),
  "AccessClearanceLevelView": () => import("./AccessClearanceLevelView"),
  "AnomalyFlagMarker": () => import("./AnomalyFlagMarker"),
  "HRReviewCommentBox": () => import("./HRReviewCommentBox"),
  "CultureMatchWidget": () => import("./CultureMatchWidget"),
  "ReferralInfoTag": () => import("./ReferralInfoTag")
};

interface WidgetLoaderProps {
  widgets: string[];
  candidateId: string;
  className?: string;
}

export const WidgetLoader: FC<WidgetLoaderProps> = ({ widgets, candidateId, className }) => {
  const { can } = usePermission();
  const { enabledWidgets, priority } = useHRWidgetConfig(candidateId);

  const sortedWidgets = useMemo(() => {
    return widgets
      .filter(name => enabledWidgets.includes(name))
      .sort((a, b) => (priority[a] ?? 100) - (priority[b] ?? 100));
  }, [widgets, enabledWidgets, priority]);

  return (
    <div className={cn("grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4", className)}>
      {sortedWidgets.map(widgetName => {
        const LazyWidget = lazy(widgetMap[widgetName] ?? widgetMap["FallbackWidget"]);
        return (
          <ErrorBoundary
            key={widgetName}
            fallbackRender={({ error }) => (
              <FallbackWidget widgetName={widgetName} error={error} />
            )}
          >
            <Suspense fallback={<Skeleton className="h-[120px] w-full" />}>
              <WidgetContainer title={widgetName}>
                <LazyWidget candidateId={candidateId} />
              </WidgetContainer>
            </Suspense>
          </ErrorBoundary>
        );
      })}
    </div>
  );
};
