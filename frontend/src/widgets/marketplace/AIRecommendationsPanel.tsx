import { useEffect, useMemo, useState } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { fetchAIRecommendations } from "@/services/api/recommendationService";
import { ProductCard } from "@/features/product/ProductCard";
import { useDebounce } from "@/shared/hooks/useDebounce";
import { AIRecommendation, InterestProfile } from "@/types/ai";
import { cn } from "@/shared/utils/classNames";
import { Logger } from "@/shared/utils/logger";
import { FilterPanel } from "@/features/product/FilterPanel";

interface AIRecommendationsPanelProps {
  userId: string;
  interests: InterestProfile;
  className?: string;
}

export const AIRecommendationsPanel = ({
  userId,
  interests,
  className,
}: AIRecommendationsPanelProps) => {
  const [recommendations, setRecommendations] = useState<AIRecommendation[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [filter, setFilter] = useState<Record<string, string | number>>({});
  const debouncedFilter = useDebounce(filter, 300);
  const [error, setError] = useState<string | null>(null);

  const loadRecommendations = async () => {
    try {
      setLoading(true);
      const data = await fetchAIRecommendations(userId, interests, debouncedFilter);
      setRecommendations(data);
    } catch (err) {
      Logger.error("Failed to fetch AI recommendations", err);
      setError("Не удалось загрузить рекомендации.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadRecommendations();
  }, [userId, JSON.stringify(interests), JSON.stringify(debouncedFilter)]);

  const filteredRecommendations = useMemo(() => {
    return recommendations.filter((rec) => rec.relevanceScore > 0.4);
  }, [recommendations]);

  if (loading) {
    return (
      <div className={cn("grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-4", className)}>
        {Array.from({ length: 8 }).map((_, i) => (
          <Skeleton key={i} className="h-[240px] w-full rounded-lg" />
        ))}
      </div>
    );
  }

  if (error) {
    return (
      <div className="text-center text-destructive font-semibold text-sm py-4">{error}</div>
    );
  }

  return (
    <div className={cn("space-y-6", className)}>
      <div className="w-full">
        <FilterPanel filters={filter} onChange={setFilter} />
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-4">
        {filteredRecommendations.map((rec) => (
          <TooltipProvider key={rec.product.id} delayDuration={100}>
            <Tooltip>
              <TooltipTrigger asChild>
                <Card className="hover:shadow-xl transition-shadow duration-200">
                  <CardContent className="p-0">
                    <ProductCard product={rec.product} />
                  </CardContent>
                </Card>
              </TooltipTrigger>
              <TooltipContent side="top" className="max-w-xs text-xs font-mono">
                relevance: {rec.relevanceScore.toFixed(3)} | model: {rec.modelId}
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
        ))}
      </div>
    </div>
  );
};
