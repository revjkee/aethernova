import { FC, useMemo, useCallback } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Tooltip } from "recharts";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { useAIExplain } from "@/features/xai/hooks/useAIExplain";
import { usePermission } from "@/shared/hooks/usePermission";
import { useCandidateData } from "@/widgets/HR/hooks/useCandidateData";
import { useAssignAgent } from "@/features/hr-control/hooks/useAssignAgent";
import { CandidateProfile } from "@/entities/candidate/types";
import { Role } from "@/shared/constants/roles";
import { InfoIcon, CheckIcon, XIcon, SparklesIcon } from "lucide-react";

interface Props {
  candidateId: string;
  compact?: boolean;
}

export const CandidateProfileCard: FC<Props> = ({ candidateId, compact = false }) => {
  const { candidate, loading } = useCandidateData(candidateId);
  const { explain, isExplaining } = useAIExplain(candidateId);
  const { can } = usePermission();
  const assignAgent = useAssignAgent();

  const handleAssign = useCallback(() => {
    assignAgent(candidateId);
  }, [assignAgent, candidateId]);

  const competencyData = useMemo(() => {
    if (!candidate) return [];
    return candidate.skills.map(skill => ({
      subject: skill.name,
      A: skill.level,
      fullMark: 10,
    }));
  }, [candidate]);

  if (loading || !candidate) {
    return (
      <Card className={cn("w-full", compact && "max-w-md")}>
        <CardHeader>
          <Skeleton className="h-6 w-48 mb-2" />
          <Skeleton className="h-4 w-32" />
        </CardHeader>
        <CardContent className="space-y-4">
          <Skeleton className="h-24 w-full rounded-xl" />
          <Skeleton className="h-10 w-full" />
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className={cn("transition-shadow hover:shadow-xl group", compact && "max-w-md")}>
      <CardHeader>
        <div className="flex justify-between items-start">
          <div>
            <CardTitle className="text-xl">{candidate.fullName}</CardTitle>
            <p className="text-muted-foreground text-sm">{candidate.position}</p>
          </div>
          <div className="flex gap-2">
            {candidate.status === "approved" && <CheckIcon className="text-green-500" />}
            {candidate.status === "rejected" && <XIcon className="text-red-500" />}
            {candidate.status === "pending" && <InfoIcon className="text-yellow-500" />}
          </div>
        </div>
        <div className="mt-2 flex flex-wrap gap-2">
          {candidate.tags.map((tag, idx) => (
            <Badge key={idx} variant="secondary">{tag}</Badge>
          ))}
        </div>
      </CardHeader>

      <CardContent className="space-y-6">
        <div className="text-sm text-muted-foreground whitespace-pre-line">
          {candidate.bio || "Нет описания"}
        </div>

        <div className="w-full h-64">
          <RadarChart outerRadius={100} width={300} height={250} data={competencyData}>
            <PolarGrid />
            <PolarAngleAxis dataKey="subject" />
            <PolarRadiusAxis angle={30} domain={[0, 10]} />
            <Radar name="Навыки" dataKey="A" stroke="#8884d8" fill="#8884d8" fillOpacity={0.6} />
            <Tooltip />
          </RadarChart>
        </div>

        <div className="flex flex-col md:flex-row gap-4 justify-between items-center">
          {can(Role.HR) && (
            <Button onClick={handleAssign} className="w-full md:w-auto">
              Назначить AI-наставника
            </Button>
          )}
          {can(Role.SUPERVISOR) && (
            <Button
              onClick={() => explain()}
              disabled={isExplaining}
              className="w-full md:w-auto"
              variant="outline"
            >
              <SparklesIcon className="w-4 h-4 mr-2" />
              AI-анализ профиля
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
  );
};
