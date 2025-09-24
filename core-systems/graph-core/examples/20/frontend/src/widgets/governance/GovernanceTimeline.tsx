// src/widgets/Governance/GovernanceTimeline.tsx

import React, { useMemo, useState } from 'react';
import { Card, CardHeader, CardContent } from '@/components/ui/card';
import { useGovernanceTimeline } from '@/hooks/governance/useGovernanceTimeline';
import { Skeleton } from '@/components/ui/skeleton';
import { Timeline, TimelineItem } from '@/components/ui/timeline';
import { cn } from '@/lib/utils';
import { formatDistanceToNowStrict } from 'date-fns';
import { ru } from 'date-fns/locale';
import {
  ActionTypeIcon,
  actionTypeLabel,
  actionTypeColor,
  GovernanceAction,
} from '@/lib/constants/governance';
import { FilterToggle } from '@/components/ui/filters/FilterToggle';
import { GovernanceTimelineFilters } from '@/types/governance';

interface Props {
  daoId: string;
}

export const GovernanceTimeline: React.FC<Props> = ({ daoId }) => {
  const { data, loading } = useGovernanceTimeline(daoId);
  const [filters, setFilters] = useState<GovernanceTimelineFilters>({
    votes: true,
    proposals: true,
    delegates: true,
    upgrades: true,
    ethics: true,
    zkProofs: true,
  });

  const filteredEvents = useMemo(() => {
    if (!data) return [];
    return data.events.filter((e: GovernanceAction) => filters[e.type]);
  }, [data, filters]);

  return (
    <Card className="w-full bg-card/80 border border-border/30 shadow-xl backdrop-blur rounded-xl">
      <CardHeader className="pb-2">
        <div className="flex justify-between items-center">
          <div>
            <h3 className="text-lg font-bold">Хронология управления DAO</h3>
            <p className="text-muted-foreground text-sm">
              Все действия, ZK-доказательства, голоса и изменения
            </p>
          </div>
          <FilterToggle
            filters={filters}
            onToggle={setFilters}
            availableFilters={{
              votes: 'Голосования',
              proposals: 'Предложения',
              delegates: 'Делегаты',
              upgrades: 'Обновления',
              ethics: 'Этика',
              zkProofs: 'ZK',
            }}
          />
        </div>
      </CardHeader>

      <CardContent className="pt-0 px-3 max-h-[640px] overflow-y-auto custom-scroll">
        {loading || !data ? (
          <Skeleton className="w-full h-[280px] rounded-lg" />
        ) : (
          <Timeline>
            {filteredEvents.map((event: GovernanceAction, index: number) => (
              <TimelineItem
                key={`${event.txHash}-${index}`}
                icon={
                  <ActionTypeIcon
                    type={event.type}
                    className={cn('w-5 h-5', actionTypeColor(event.type))}
                  />
                }
                label={actionTypeLabel(event.type)}
                timestamp={formatDistanceToNowStrict(new Date(event.timestamp), {
                  addSuffix: true,
                  locale: ru,
                })}
                title={event.title}
                description={event.description}
                status={event.status}
                txHash={event.txHash}
                actor={event.actor}
                target={event.target}
                zkVerified={event.zkVerified}
              />
            ))}
          </Timeline>
        )}
      </CardContent>
    </Card>
  );
};

export default GovernanceTimeline;
