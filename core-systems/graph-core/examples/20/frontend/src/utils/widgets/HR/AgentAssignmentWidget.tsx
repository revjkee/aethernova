import { FC, useCallback, useEffect, useMemo, useState } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { toast } from "@/components/ui/use-toast";
import { usePermission } from "@/shared/hooks/usePermission";
import { Role } from "@/shared/constants/roles";
import { useAvailableAgents } from "@/features/agents/hooks/useAvailableAgents";
import { useAgentAssignment } from "@/features/agents/hooks/useAgentAssignment";
import { useAISuggestedAgent } from "@/features/xai/hooks/useAISuggestedAgent";
import { AIAgentExplanation } from "@/features/xai/components/AIAgentExplanation";
import { AgentProfile } from "@/entities/agents/types";
import { Loader2Icon, UserPlusIcon, UserXIcon } from "lucide-react";

interface Props {
  candidateId: string;
  currentAgentId?: string;
  compact?: boolean;
}

export const AgentAssignmentWidget: FC<Props> = ({ candidateId, currentAgentId, compact = false }) => {
  const { can } = usePermission();
  const { agents, loading: loadingAgents } = useAvailableAgents();
  const {
    assignAgent,
    unassignAgent,
    loading: actionLoading
  } = useAgentAssignment(candidateId);

  const { suggestedAgent, explanation, loading: loadingAI } = useAISuggestedAgent(candidateId);

  const [selectedAgentId, setSelectedAgentId] = useState<string | null>(null);
  const [assigning, setAssigning] = useState(false);
  const [unassigning, setUnassigning] = useState(false);

  useEffect(() => {
    if (suggestedAgent?.id) {
      setSelectedAgentId(suggestedAgent.id);
    }
  }, [suggestedAgent]);

  const availableOptions = useMemo(() => {
    return agents?.map((agent: AgentProfile) => ({
      label: `${agent.fullName} — ${agent.specialty}`,
      value: agent.id
    })) || [];
  }, [agents]);

  const handleAssign = useCallback(async () => {
    if (!selectedAgentId || !can(Role.HR)) {
      toast({ title: "Ошибка", description: "Недостаточно прав или не выбран агент" });
      return;
    }

    setAssigning(true);
    try {
      await assignAgent(selectedAgentId);
      toast({ title: "Агент назначен", description: "AI-наставник успешно привязан" });
    } catch {
      toast({ title: "Ошибка", description: "Не удалось назначить агента" });
    } finally {
      setAssigning(false);
    }
  }, [selectedAgentId, can, assignAgent]);

  const handleUnassign = useCallback(async () => {
    if (!currentAgentId || !can(Role.HR)) {
      toast({ title: "Ошибка", description: "Недостаточно прав для открепления" });
      return;
    }

    setUnassigning(true);
    try {
      await unassignAgent();
      toast({ title: "Агент откреплён", description: "Наставник удалён от кандидата" });
    } catch {
      toast({ title: "Ошибка", description: "Не удалось открепить агента" });
    } finally {
      setUnassigning(false);
    }
  }, [currentAgentId, can, unassignAgent]);

  if (loadingAgents || loadingAI) {
    return (
      <Card className={compact ? "max-w-md" : "w-full"}>
        <CardHeader>
          <Skeleton className="h-6 w-64 mb-2" />
          <Skeleton className="h-4 w-32" />
        </CardHeader>
        <CardContent>
          <Skeleton className="h-24 w-full rounded-md" />
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className={`transition-shadow hover:shadow-md ${compact ? "max-w-md" : "w-full"}`}>
      <CardHeader>
        <CardTitle className="text-lg">Назначение AI-наставника</CardTitle>
        <p className="text-sm text-muted-foreground">Привязка агента для сопровождения или оценки</p>
      </CardHeader>

      <CardContent className="space-y-4">
        <Select
          value={selectedAgentId || ""}
          onValueChange={setSelectedAgentId}
          disabled={assigning || unassigning}
        >
          <SelectTrigger className="w-full">
            <SelectValue placeholder="Выбрать AI-агента" />
          </SelectTrigger>
          <SelectContent>
            {availableOptions.map(opt => (
              <SelectItem key={opt.value} value={opt.value}>
                {opt.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        <div className="flex gap-3">
          <Button
            onClick={handleAssign}
            disabled={!selectedAgentId || assigning}
            className="flex items-center min-w-[160px]"
          >
            {assigning ? (
              <Loader2Icon className="w-4 h-4 mr-2 animate-spin" />
            ) : (
              <UserPlusIcon className="w-4 h-4 mr-2" />
            )}
            Назначить
          </Button>

          {currentAgentId && (
            <Button
              onClick={handleUnassign}
              disabled={unassigning}
              variant="destructive"
              className="flex items-center min-w-[160px]"
            >
              {unassigning ? (
                <Loader2Icon className="w-4 h-4 mr-2 animate-spin" />
              ) : (
                <UserXIcon className="w-4 h-4 mr-2" />
              )}
              Открепить
            </Button>
          )}
        </div>

        {suggestedAgent && (
          <div className="text-sm text-muted-foreground">
            <p className="font-semibold mb-1">AI рекомендует: <Badge>{suggestedAgent.fullName}</Badge></p>
            {explanation && <AIAgentExplanation explanation={explanation} />}
          </div>
        )}
      </CardContent>
    </Card>
  );
};
