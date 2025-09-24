// src/widgets/Governance/ProposalVotingCountdown.tsx

import React, { useEffect, useState, useRef } from 'react';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { calculateTimeLeft, formatTimeLeft, isExpired } from '@/lib/timeUtils';
import { useGovernanceClock } from '@/hooks/useGovernanceClock';
import { cn } from '@/lib/utils';
import { TimerIcon, AlertIcon } from '@/components/icons';
import { ProposalStatus } from '@/types/governance';

interface ProposalVotingCountdownProps {
  endTimestamp: string; // ISO UTC
  proposalId: string;
  status: ProposalStatus;
  onExpire?: (id: string) => void;
}

export const ProposalVotingCountdown: React.FC<ProposalVotingCountdownProps> = ({
  endTimestamp,
  proposalId,
  status,
  onExpire
}) => {
  const [timeLeft, setTimeLeft] = useState(() => calculateTimeLeft(endTimestamp));
  const [percentElapsed, setPercentElapsed] = useState(0);
  const intervalRef = useRef<NodeJS.Timeout | null>(null);
  const syncedNow = useGovernanceClock(); // global governance-synced UTC

  const expired = isExpired(endTimestamp);

  useEffect(() => {
    const updateCountdown = () => {
      const now = syncedNow();
      const end = new Date(endTimestamp).getTime();
      const duration = end - now.start;
      const total = end - now.anchor;
      const elapsed = total - duration;

      if (duration <= 0) {
        setTimeLeft({ hours: 0, minutes: 0, seconds: 0 });
        setPercentElapsed(100);
        clearInterval(intervalRef.current as NodeJS.Timeout);
        if (onExpire) onExpire(proposalId);
        return;
      }

      setTimeLeft(calculateTimeLeft(endTimestamp));
      setPercentElapsed(Math.min(100, Math.max(0, (elapsed / total) * 100)));
    };

    intervalRef.current = setInterval(updateCountdown, 1000);
    updateCountdown();

    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [endTimestamp, proposalId, syncedNow, onExpire]);

  const timeDisplay = formatTimeLeft(timeLeft);
  const critical = timeLeft.hours === 0 && timeLeft.minutes <= 5;

  return (
    <div
      className={cn(
        'flex flex-col items-start justify-start w-full',
        expired && 'opacity-50 pointer-events-none select-none'
      )}
      role="timer"
      aria-label={`Voting time left: ${timeDisplay}`}
    >
      <div className="flex items-center gap-2 mb-1">
        <TimerIcon className={cn('w-4 h-4', critical && 'text-red-500 animate-pulse')} />
        <Tooltip>
          <TooltipTrigger>
            <Badge
              variant={critical ? 'destructive' : 'outline'}
              className={cn('font-mono tracking-tight text-xs px-2 py-0.5 rounded-sm', critical && 'border-red-500')}
            >
              {expired ? 'Expired' : timeDisplay}
            </Badge>
          </TooltipTrigger>
          <TooltipContent>
            {expired ? 'Голосование завершено' : 'Оставшееся время до завершения голосования'}
          </TooltipContent>
        </Tooltip>
      </div>

      <Progress
        className={cn(
          'h-2 w-full rounded-full transition-all duration-300',
          percentElapsed > 90 && 'bg-red-500/40'
        )}
        value={percentElapsed}
        indicatorClass={cn(
          'bg-primary rounded-full transition-all',
          percentElapsed > 95 && 'bg-red-600 animate-pulse'
        )}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={Math.floor(percentElapsed)}
        aria-label="Progress of voting window"
      />
    </div>
  );
};
