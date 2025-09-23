import { FC, useMemo, useState } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { useTeamAnalytics } from "@/features/hr-core/hooks/useTeamAnalytics";
import { TeamRadarChart } from "@/features/hr-core/components/TeamRadarChart";
import { TeamGraph } from "@/features/hr-core/components/TeamGraph";
import { AIGroupSummary } from "@/features/xai/components/AIGroupSummary";
import { usePermission } from "@/shared/hooks/usePermission";
import { Role } from "@/shared/constants/roles";
import { Button } from "@/components/ui/button";
import { RefreshCcwIcon } from "lucide-react";
import { TeamMember } from "@/entities/team/types";

interface Props {
  departmentId: string;
  compact?: boolean;
}

export const TeamInsightsWidget: FC<Props> = ({ departmentId, compact = false }) => {
  const { can } = usePermission();
  const [filterRole, setFilterRole] = useState<string | null>(null);

  const {
    loading,
    team,
    competencies,
    summary,
    refresh
  } = useTeamAnalytics(departmentId, filterRole);

  const filteredTeam = useMemo<TeamMember[]>(() => {
    if (!team) return [];
    return filterRole ? team.filter(member => member.role === filterRole) : team;
  }, [team, filterRole]);

  if (loading || !team || !competencies || !summary) {
    return (
      <Card className={cn("w-full", compact && "max-w-4xl")}>
        <CardHeader>
          <Skeleton className="h-6 w-64 mb-2" />
          <Skeleton className="h-4 w-32" />
        </CardHeader>
        <CardContent>
          <Skeleton className="h-[300px] w-full rounded-xl" />
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className={cn("transition-shadow hover:shadow-xl", compact && "max-w-4xl")}>
      <CardHeader className="flex flex-col md:flex-row justify-between md:items-center">
        <div>
          <CardTitle className="text-xl">Командный профиль: AI-аналитика</CardTitle>
          <p className="text-muted-foreground text-sm">
            Компетенции, взаимодействия и риски дисбаланса в команде
          </p>
        </div>

        <div className="flex gap-2 mt-4 md:mt-0 items-center">
          <Select value={filterRole || ""} onValueChange={setFilterRole}>
            <SelectTrigger className="w-[200px]">
              <SelectValue placeholder="Фильтр по роли" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="">Все роли</SelectItem>
              <SelectItem value="engineer">Инженеры</SelectItem>
              <SelectItem value="designer">Дизайнеры</SelectItem>
              <SelectItem value="pm">Проект-менеджеры</SelectItem>
              <SelectItem value="qa">QA</SelectItem>
            </SelectContent>
          </Select>

          <Button size="icon" onClick={() => refresh()}>
            <RefreshCcwIcon className="w-4 h-4" />
          </Button>
        </div>
      </CardHeader>

      <CardContent className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <div className="space-y-4">
          <h3 className="text-base font-semibold">Граф взаимодействия</h3>
          <TeamGraph team={filteredTeam} />
          <div className="flex flex-wrap gap-2">
            {filteredTeam.map((member, idx) => (
              <Badge key={idx} variant="outline">
                {member.fullName} — {member.role}
              </Badge>
            ))}
          </div>
        </div>

        <div className="space-y-4">
          <h3 className="text-base font-semibold">Радар компетенций</h3>
          <TeamRadarChart data={competencies} />
        </div>
      </CardContent>

      {can(Role.SUPERVISOR) && (
        <CardContent className="mt-6">
          <AIGroupSummary summary={summary} title="AI-групповой анализ: сильные и слабые стороны" />
        </CardContent>
      )}
    </Card>
  );
};
