import { FC, useMemo, useState } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { usePermission } from "@/shared/hooks/usePermission";
import { Role } from "@/shared/constants/roles";
import { useInterviewFeedback } from "@/features/hr-core/hooks/useInterviewFeedback";
import { FeedbackRadarChart } from "@/features/hr-core/components/FeedbackRadarChart";
import { XAIExplanation } from "@/features/xai/components/XAIExplanation";
import { Button } from "@/components/ui/button";
import { ReloadIcon } from "lucide-react";
import { retryInterviewAssessment } from "@/features/hr-core/api/retryAssessment";
import { toast } from "@/components/ui/use-toast";

interface Props {
  candidateId: string;
  compact?: boolean;
}

export const AIInterviewFeedback: FC<Props> = ({ candidateId, compact = false }) => {
  const { can } = usePermission();
  const { feedback, loading, refetch } = useInterviewFeedback(candidateId);
  const [retesting, setRetesting] = useState(false);

  const scoreLevel = useMemo(() => {
    if (!feedback) return null;
    const avg = feedback.scores.reduce((acc, s) => acc + s.value, 0) / feedback.scores.length;
    if (avg >= 8) return "Отлично";
    if (avg >= 6) return "Хорошо";
    if (avg >= 4) return "Удовлетворительно";
    return "Слабо";
  }, [feedback]);

  const handleRetest = async () => {
    setRetesting(true);
    try {
      await retryInterviewAssessment(candidateId);
      toast({
        title: "Повторный анализ запущен",
        description: "AI пересчитает интервью в течение нескольких минут"
      });
      refetch();
    } catch (e) {
      toast({
        title: "Ошибка",
        description: "Не удалось инициировать повторную оценку"
      });
    } finally {
      setRetesting(false);
    }
  };

  if (loading || !feedback) {
    return (
      <Card className={compact ? "max-w-xl" : "w-full"}>
        <CardHeader>
          <Skeleton className="h-6 w-64 mb-2" />
          <Skeleton className="h-4 w-32" />
        </CardHeader>
        <CardContent>
          <Skeleton className="h-[300px] w-full rounded-lg" />
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className={`transition-shadow hover:shadow-md ${compact ? "max-w-xl" : "w-full"}`}>
      <CardHeader className="flex flex-col md:flex-row justify-between md:items-center">
        <div>
          <CardTitle className="text-xl">AI-фидбек по интервью</CardTitle>
          <p className="text-sm text-muted-foreground">Оценка компетенций, сильных и слабых зон</p>
        </div>

        {can(Role.HR) && (
          <Button onClick={handleRetest} size="sm" variant="outline" disabled={retesting}>
            <ReloadIcon className="w-4 h-4 mr-2 animate-spin" style={{ visibility: retesting ? 'visible' : 'hidden' }} />
            {retesting ? "Повтор..." : "Повторный анализ"}
          </Button>
        )}
      </CardHeader>

      <CardContent className="space-y-6">
        <div className="flex flex-wrap gap-2">
          <Badge variant="outline">Общая оценка: {scoreLevel}</Badge>
          <Badge variant="secondary">Дата интервью: {feedback.date}</Badge>
        </div>

        <FeedbackRadarChart scores={feedback.scores} />

        {feedback.aiSummary && (
          <div className="bg-muted p-4 rounded-lg border">
            <p className="text-sm text-muted-foreground mb-2 font-semibold">AI-анализ:</p>
            <p className="text-sm whitespace-pre-line">{feedback.aiSummary}</p>
          </div>
        )}

        {feedback.explanation && (
          <div className="mt-4">
            <XAIExplanation explanation={feedback.explanation} title="Объяснение оценок от AI" />
          </div>
        )}
      </CardContent>
    </Card>
  );
};
