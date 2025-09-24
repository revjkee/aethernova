// src/widgets/Governance/ProposalListWidget.tsx

import React, { useMemo, useState, useEffect } from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import { cn } from '@/lib/utils';
import { ProposalStatus, GovernanceProposal } from '@/types/governance';
import { formatDistanceToNow } from 'date-fns';
import { useProposals } from '@/services/hooks/useGovernance';
import { FilterBar } from '@/widgets/shared/FilterBar';
import { Skeleton } from '@/components/ui/skeleton';
import { AnimatePresence, motion } from 'framer-motion';

interface ProposalListWidgetProps {
  agentId?: string;
}

const statusLabels: Record<ProposalStatus, string> = {
  active: 'Активно',
  passed: 'Принято',
  rejected: 'Отклонено',
  queued: 'В очереди',
  executed: 'Исполнено',
  draft: 'Черновик',
};

export const ProposalListWidget: React.FC<ProposalListWidgetProps> = ({ agentId }) => {
  const [filter, setFilter] = useState<ProposalStatus | 'all'>('all');
  const [search, setSearch] = useState('');
  const { data: proposals, isLoading } = useProposals(agentId);

  const filtered = useMemo(() => {
    if (!proposals) return [];
    return proposals.filter((p) => {
      const matchStatus = filter === 'all' || p.status === filter;
      const matchSearch = p.title.toLowerCase().includes(search.toLowerCase());
      return matchStatus && matchSearch;
    });
  }, [proposals, filter, search]);

  return (
    <Card className="h-full flex flex-col overflow-hidden">
      <CardContent className="flex flex-col gap-4 p-4 h-full">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-2">
          <Input
            placeholder="Поиск по предложениям"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="max-w-md w-full"
          />
          <FilterBar
            options={['all', 'active', 'passed', 'rejected', 'queued', 'executed', 'draft']}
            value={filter}
            onChange={setFilter}
            labels={statusLabels}
          />
        </div>

        <ScrollArea className="flex-grow pr-2">
          <div className="space-y-2">
            {isLoading ? (
              Array.from({ length: 5 }).map((_, idx) => (
                <Skeleton key={idx} className="h-[64px] rounded-md w-full" />
              ))
            ) : (
              <AnimatePresence>
                {filtered.map((proposal) => (
                  <motion.div
                    key={proposal.id}
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -8 }}
                    transition={{ duration: 0.2 }}
                    className={cn(
                      'bg-muted border border-border rounded-xl p-3 transition-all hover:border-accent'
                    )}
                  >
                    <div className="flex justify-between items-start">
                      <div className="flex flex-col">
                        <span className="font-semibold text-base leading-tight">
                          {proposal.title}
                        </span>
                        <span className="text-sm text-muted-foreground">
                          {formatDistanceToNow(new Date(proposal.createdAt), { addSuffix: true })}
                        </span>
                      </div>
                      <Badge variant="outline" className="text-xs shrink-0 capitalize">
                        {statusLabels[proposal.status]}
                      </Badge>
                    </div>
                  </motion.div>
                ))}
              </AnimatePresence>
            )}
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );
};

export default ProposalListWidget;
