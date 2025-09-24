import { FC, useCallback, useMemo, useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { usePermission } from "@/shared/hooks/usePermission";
import { Role } from "@/shared/constants/roles";
import { useCandidateActions } from "@/features/hr-core/hooks/useCandidateActions";
import { toast } from "@/components/ui/use-toast";
import { cn } from "@/lib/utils";
import { Loader2Icon, CheckCircleIcon, XCircleIcon, CalendarClockIcon, UndoIcon } from "lucide-react";
import { useAIActionRecommendation } from "@/features/xai/hooks/useAIActionRecommendation";

interface Props {
  candidateId: string;
  currentStatus: "pending" | "approved" | "rejected" | "interview";
  compact?: boolean;
}

export const HRQuickActionsPanel: FC<Props> = ({ candidateId, currentStatus, compact = false }) => {
  const { can } = usePermission();
  const { recommendAction, loading: loadingAI } = useAIActionRecommendation(candidateId);
  const {
    acceptCandidate,
    rejectCandidate,
    scheduleInterview,
    rollbackAction,
    loading: actionLoading
  } = useCandidateActions(candidateId);

  const [actionState, setActionState] = useState<null | "accept" | "reject" | "interview" | "rollback">(null);

  const handleAction = useCallback(async (type: "accept" | "reject" | "interview" | "rollback") => {
    if (!can(Role.HR)) {
      toast({ title: "Нет доступа", description: "У вас нет прав на выполнение этого действия" });
      return;
    }

    setActionState(type);
    try {
      if (type === "accept") await acceptCandidate();
      if (type === "reject") await rejectCandidate();
      if (type === "interview") await scheduleInterview();
      if (type === "rollback") await rollbackAction();
      toast({ title: "Успешно", description: "Действие выполнено" });
    } catch {
      toast({ title: "Ошибка", description: "Не удалось выполнить действие" });
    } finally {
      setActionState(null);
    }
  }, [can, acceptCandidate, rejectCandidate, scheduleInterview, rollbackAction]);

  const availableActions = useMemo(() => {
    const actions: { type: "accept" | "reject" | "interview" | "rollback"; label: string; icon: JSX.Element }[] = [];

    if (currentStatus === "pending") {
      actions.push({
        type: "accept",
        label: "Принять",
        icon: <CheckCircleIcon className="w-4 h-4 mr-2" />
      });
      actions.push({
        type: "reject",
        label: "Отклонить",
        icon: <XCircleIcon className="w-4 h-4 mr-2" />
      });
      actions.push({
        type: "interview",
        label: "Вызвать на интервью",
        icon: <CalendarClockIcon className="w-4 h-4 mr-2" />
      });
    } else {
      actions.push({
        type: "rollback",
        label: "Откатить решение",
        icon: <UndoIcon className="w-4 h-4 mr-2" />
      });
    }

    return actions;
  }, [currentStatus]);

  return (
    <Card className={cn("w-full", compact && "max-w-md", "transition-shadow hover:shadow-md")}>
      <CardHeader>
        <CardTitle className="text-lg">Быстрые действия HR</CardTitle>
        <p className="text-sm text-muted-foreground">
          Управление статусом кандидата и вызов на интервью
        </p>
      </CardHeader>

      <CardContent className="space-y-4">
        <div className="flex flex-wrap gap-3">
          {availableActions.map(action => (
            <Button
              key={action.type}
              onClick={() => handleAction(action.type)}
              disabled={actionLoading || actionState !== null}
              variant={action.type === "reject" ? "destructive" : "default"}
              className="min-w-[180px] flex items-center"
            >
              {actionState === action.type ? (
                <Loader2Icon className="animate-spin w-4 h-4 mr-2" />
              ) : (
                action.icon
              )}
              {action.label}
            </Button>
          ))}
        </div>

        {can(Role.SUPERVISOR) && !loadingAI && recommendAction && (
          <div className="bg-muted p-3 rounded-md border">
            <p className="text-sm text-muted-foreground mb-1 font-semibold">
              Рекомендация AI:
            </p>
            <p className="text-sm whitespace-pre-line">{recommendAction}</p>
          </div>
        )}
      </CardContent>
    </Card>
  );
};
