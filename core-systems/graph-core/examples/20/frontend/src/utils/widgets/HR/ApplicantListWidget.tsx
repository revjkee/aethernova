import React, { useState, useEffect, useMemo, useCallback } from "react";
import { FixedSizeList as VirtualizedList } from "react-window";
import { useTranslation } from "react-i18next";
import { useTheme } from "@/shared/hooks/useTheme";
import { usePermission } from "@/shared/hooks/usePermission";
import { useApplicantStore } from "@/features/hr/store/applicantStore";
import { useAIInsight } from "@/features/ai_insight/hooks/useAIInsight";
import { useLogAction } from "@/shared/hooks/useLogAction";
import { ApplicantCard } from "./CandidateProfileCard";
import { SearchBar } from "@/shared/ui/SearchBar";
import { FilterPanel } from "@/shared/ui/FilterPanel";
import { Pagination } from "@/shared/ui/Pagination";
import { Spinner } from "@/shared/ui/Spinner";
import { ErrorFallback } from "@/shared/ui/ErrorFallback";
import { RBACGuard } from "@/shared/ui/RBACGuard";
import { Applicant, InsightData } from "@/features/hr/models/Applicant";
import { AnimatePresence, motion } from "framer-motion";
import { EmptyState } from "@/shared/ui/EmptyState";
import { WidgetContainer } from "@/widgets/common/WidgetContainer";
import { applySmartFilters } from "../utils/applicantUtils";
import { useDebounce } from "@/shared/hooks/useDebounce";
import { useZeroTrustContext } from "@/shared/security/useZeroTrustContext";
import { ApplicantHighlightOverlay } from "./ApplicantHighlightOverlay";

const ITEM_HEIGHT = 132;
const PAGE_SIZE = 20;

export const ApplicantListWidget: React.FC = () => {
  const { t } = useTranslation();
  const { theme } = useTheme();
  const { hasAccess } = usePermission();
  const { isRestricted } = useZeroTrustContext();
  const { fetchApplicants, applicants, isLoading, error } = useApplicantStore();
  const { getInsightsForApplicants } = useAIInsight();
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const [insights, setInsights] = useState<Record<string, InsightData>>({});
  const debouncedQuery = useDebounce(query, 300);
  const log = useLogAction("ApplicantList.View");

  const startIndex = (page - 1) * PAGE_SIZE;
  const endIndex = startIndex + PAGE_SIZE;

  const visibleApplicants = useMemo(() => {
    const filtered = applySmartFilters(applicants, debouncedQuery);
    return filtered.slice(startIndex, endIndex);
  }, [applicants, debouncedQuery, page]);

  useEffect(() => {
    fetchApplicants().then((loaded) => {
      if (loaded) {
        const ids = loaded.map((a) => a.id);
        getInsightsForApplicants(ids).then(setInsights);
      }
    });
  }, [fetchApplicants, getInsightsForApplicants]);

  useEffect(() => {
    log("opened_list", { query, page });
  }, [query, page]);

  const renderRow = useCallback(
    ({ index, style }) => {
      const applicant = visibleApplicants[index];
      if (!applicant) return null;
      const insight = insights[applicant.id];

      return (
        <div style={style} key={applicant.id}>
          <motion.div
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.3 }}
          >
            <ApplicantCard
              applicant={applicant}
              insight={insight}
              highlight={insight?.flags?.length > 0}
              restricted={isRestricted(applicant.id)}
            />
          </motion.div>
        </div>
      );
    },
    [visibleApplicants, insights, isRestricted]
  );

  if (isLoading) return <Spinner message={t("loading.applicants")} />;
  if (error) return <ErrorFallback title={t("error.applicants_load")} />;

  return (
    <RBACGuard roles={["HR", "Admin", "AIReviewer"]}>
      <WidgetContainer title={t("widgets.applicant_list.title")}>
        <SearchBar value={query} onChange={setQuery} placeholder={t("search.applicants")} />
        <FilterPanel entity="applicant" />
        <AnimatePresence>
          {visibleApplicants.length === 0 ? (
            <EmptyState message={t("empty.no_applicants")} />
          ) : (
            <VirtualizedList
              height={Math.min(visibleApplicants.length, PAGE_SIZE) * ITEM_HEIGHT}
              itemCount={visibleApplicants.length}
              itemSize={ITEM_HEIGHT}
              width="100%"
            >
              {renderRow}
            </VirtualizedList>
          )}
        </AnimatePresence>
        <Pagination
          total={applySmartFilters(applicants, debouncedQuery).length}
          currentPage={page}
          onPageChange={setPage}
          pageSize={PAGE_SIZE}
        />
        <ApplicantHighlightOverlay insights={insights} />
      </WidgetContainer>
    </RBACGuard>
  );
};

