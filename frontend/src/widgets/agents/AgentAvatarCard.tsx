import { FC } from "react";
import { Card, CardHeader, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { AgentStatus, AgentRole } from "@/entities/agent/types";
import { motion } from "framer-motion";
import { useTheme } from "@/shared/hooks/useTheme";
import { useAgentInfo } from "@/widgets/Agents/hooks/useAgentInfo";
import { Tooltip } from "@/components/ui/tooltip";
import { ShieldCheck, Activity, AlertCircle } from "lucide-react";

interface AgentAvatarCardProps {
  agentId: string;
  className?: string;
  size?: "sm" | "md" | "lg";
  showStatus?: boolean;
  compact?: boolean;
}

const statusColorMap: Record<AgentStatus, string> = {
  "active": "bg-green-500",
  "idle": "bg-yellow-400",
  "error": "bg-red-500",
  "offline": "bg-gray-500",
};

const roleIconMap: Record<AgentRole, React.ReactNode> = {
  governor: <ShieldCheck size={16} />,
  executor: <Activity size={16} />,
  sentinel: <AlertCircle size={16} />,
};

export const AgentAvatarCard: FC<AgentAvatarCardProps> = ({
  agentId,
  className,
  size = "md",
  showStatus = true,
  compact = false,
}) => {
  const { data, isLoading, error } = useAgentInfo(agentId);
  const { theme } = useTheme();

  if (isLoading) {
    return <Skeleton className={cn("rounded-full", className)} />;
  }

  if (error || !data) {
    return (
      <Card className={cn("p-4 text-sm text-muted-foreground", className)}>
        <div className="text-red-500">Ошибка загрузки агента</div>
      </Card>
    );
  }

  const avatarSize = {
    sm: "w-10 h-10",
    md: "w-16 h-16",
    lg: "w-24 h-24",
  }[size];

  return (
    <Card className={cn("flex items-center gap-4 transition-shadow duration-200", className)}>
      <CardHeader className={cn("p-4", compact && "p-2")}>
        <motion.div
          className={cn("relative rounded-full overflow-hidden", avatarSize)}
          whileHover={{ scale: 1.05 }}
        >
          <img
            src={data.avatarUrl}
            alt={data.name}
            className="object-cover w-full h-full"
            loading="lazy"
          />
          {showStatus && (
            <span
              className={cn(
                "absolute bottom-0 right-0 w-3 h-3 rounded-full ring-2 ring-white dark:ring-black",
                statusColorMap[data.status]
              )}
            />
          )}
        </motion.div>
      </CardHeader>
      <CardContent className="flex flex-col gap-1 p-4">
        <div className="flex items-center gap-1 font-semibold">
          {data.name}
          {roleIconMap[data.role]}
        </div>
        <Tooltip content={data.roleDescription}>
          <Badge variant="secondary" className="w-fit capitalize">
            {data.role}
          </Badge>
        </Tooltip>
        {!compact && (
          <p className="text-sm text-muted-foreground line-clamp-2 max-w-xs">
            {data.summary}
          </p>
        )}
      </CardContent>
    </Card>
  );
};
