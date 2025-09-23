import { FC, useMemo, useState } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { usePermission } from "@/shared/hooks/usePermission";
import { Role } from "@/shared/constants/roles";
import { useApplicantTimeline } from "@/features/hr-core/hooks/useApplicantTimeline";
import { TimelineItem } from "@/entities/timeline/types";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { XAIExplanation } from "@/features/xai/components/XAIExplanation";
import { useTimelineXAI } from "@/features/xai/hooks/useTimelineXAI";
import { CalendarIcon, MessageCircleIcon, UserCheckIcon, FileTextIcon } from "lucide-react";

interface Props {
  candidateId: string;
  compact?: boolean;
}

export const ApplicantTimelineView: FC<Props> = ({ candidateId, compact = false }) => {
  const { can } = usePermission();
  const { events, loading } = useApplicantTimeline(candidateId);
  const { explanation, loading: xaiLoading } = useTimelineXAI(candidateId);

  const grouped = useMemo(() => {
    if (!events) return {};
    return events.reduce<Record<string, TimelineItem[]>>((acc, item) => {
      const date = new Date(item.timestamp).toLocaleDateString();
      if (!acc[date]) acc[date] = [];
      acc[date].push(item);
      return acc;
    }, {});
  }, [events]);

  if (loading || !events) {
    return (
      <Card className={cn("w-full", compact && "max-w-3xl")}>
        <CardHeader>
          <Skeleton className="h-6 w-64 mb-2" />
          <Skeleton className="h-4 w-32" />
        </CardHeader>
        <CardContent>
          <Skeleton className="h-[300px] w-full" />
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className={cn("transition-shadow hover:shadow-md", compact && "max-w-3xl")}>
      <CardHeader>
        <CardTitle className="text-xl">Хронология взаимодействий</CardTitle>
        <p className="text-sm text-muted-foreground">События, сообщения, решения, AI-комментарии</p>
      </CardHeader>

      <CardContent className="max-h-[420px] overflow-hidden">
        <ScrollArea className="pr-2 h-full">
          <div className="space-y-8">
            {Object.entries(grouped).map(([date, items]) => (
              <div key={date}>
                <div className="text-muted-foreground text-sm font-semibold mb-2">{date}</div>
                <div className="space-y-4 pl-2 border-l-2 border-muted">
                  {items.map((item, index) => (
                    <div key={index} className="relative pl-6">
                      <div className="absolute left-[-11px] top-[2px] w-4 h-4 rounded-full bg-primary" />

                      <div className="flex justify-between items-center">
                        <div className="flex items-center gap-2">
                          {getIcon(item.type)}
                          <span className="font-medium">{item.title}</span>
                        </div>
                        <span className="text-xs text-muted-foreground">{new Date(item.timestamp).toLocaleTimeString()}</span>
                      </div>

                      <div className="text-sm text-muted-foreground mt-1 whitespace-pre-line">
                        {item.description}
                      </div>

                      {item.meta?.tags?.length > 0 && (
                        <div className="flex gap-2 mt-2 flex-wrap">
                          {item.meta.tags.map((tag, i) => (
                            <Badge key={i} variant="outline">{tag}</Badge>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </ScrollArea>

        {can(Role.SUPERVISOR) && explanation && !xaiLoading && (
          <div className="mt-6">
            <XAIExplanation explanation={explanation} title="AI-резюме взаимодействий" />
          </div>
        )}
      </CardContent>
    </Card>
  );
};

// Выбор иконки по типу события
function getIcon(type: TimelineItem["type"]) {
  switch (type) {
    case "interview":
      return <CalendarIcon className="w-4 h-4 text-muted-foreground" />;
    case "message":
      return <MessageCircleIcon className="w-4 h-4 text-muted-foreground" />;
    case "decision":
      return <UserCheckIcon className="w-4 h-4 text-muted-foreground" />;
    case "document":
      return <FileTextIcon className="w-4 h-4 text-muted-foreground" />;
    default:
      return null;
  }
}
