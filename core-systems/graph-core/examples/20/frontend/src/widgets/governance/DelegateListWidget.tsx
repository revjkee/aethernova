// src/widgets/Governance/DelegateListWidget.tsx

import React, { useEffect, useState, useMemo } from 'react';
import { Card, CardHeader, CardContent } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Badge } from '@/components/ui/badge';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { SortIcon, ShieldCheck, Users } from 'lucide-react';
import { useDelegates } from '@/hooks/governance/useDelegates';
import { cn } from '@/lib/utils';

type Delegate = {
  id: string;
  name: string;
  avatarUrl?: string;
  trustScore: number; // 0–100
  mandateCount: number;
  lastActive: number; // timestamp
  verified: boolean;
  bio?: string;
};

const DelegateListWidget: React.FC = () => {
  const { delegates, loading } = useDelegates();
  const [filter, setFilter] = useState('');
  const [sortBy, setSortBy] = useState<'trust' | 'mandates'>('trust');

  const sortedDelegates = useMemo(() => {
    const filtered = delegates.filter((d: Delegate) =>
      d.name.toLowerCase().includes(filter.toLowerCase())
    );
    return [...filtered].sort((a, b) => {
      if (sortBy === 'trust') return b.trustScore - a.trustScore;
      return b.mandateCount - a.mandateCount;
    });
  }, [delegates, filter, sortBy]);

  return (
    <Card className="bg-card/60 border border-border/30 shadow-sm backdrop-blur-sm">
      <CardHeader className="pb-2 flex flex-col md:flex-row justify-between items-start md:items-center gap-3">
        <div>
          <h3 className="text-lg font-semibold">Делегаты</h3>
          <p className="text-muted-foreground text-sm">
            Список активных делегатов, имеющих голос в DAO
          </p>
        </div>
        <div className="flex gap-2 w-full md:w-auto">
          <Input
            placeholder="Поиск по имени"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="max-w-xs"
          />
          <button
            onClick={() =>
              setSortBy((prev) => (prev === 'trust' ? 'mandates' : 'trust'))
            }
            className="text-sm flex items-center gap-1 text-muted-foreground hover:text-foreground transition"
          >
            <SortIcon className="w-4 h-4" />
            {sortBy === 'trust' ? 'По доверию' : 'По мандатам'}
          </button>
        </div>
      </CardHeader>

      <CardContent className="p-0">
        <ScrollArea className="h-[420px] overflow-y-auto px-4">
          {loading ? (
            <div className="p-6 text-center text-muted-foreground">Загрузка...</div>
          ) : sortedDelegates.length === 0 ? (
            <div className="p-6 text-center text-muted-foreground">
              Нет делегатов по заданным параметрам
            </div>
          ) : (
            <ul className="divide-y divide-border/20">
              {sortedDelegates.map((delegate) => (
                <li
                  key={delegate.id}
                  className="flex items-start py-4 gap-4 hover:bg-accent/10 transition rounded-md px-2"
                >
                  <Avatar className="w-12 h-12">
                    <AvatarImage src={delegate.avatarUrl} alt={delegate.name} />
                    <AvatarFallback>
                      {delegate.name.slice(0, 2).toUpperCase()}
                    </AvatarFallback>
                  </Avatar>

                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <span className="font-medium">{delegate.name}</span>
                      {delegate.verified && (
                        <ShieldCheck className="w-4 h-4 text-green-500" />
                      )}
                    </div>

                    {delegate.bio && (
                      <p className="text-sm text-muted-foreground line-clamp-2 mt-1">
                        {delegate.bio}
                      </p>
                    )}

                    <div className="flex items-center gap-2 mt-2 flex-wrap">
                      <Badge variant="outline">
                        TrustScore: <span className="ml-1 font-bold">{delegate.trustScore}</span>
                      </Badge>
                      <Badge variant="secondary">
                        Мандаты: <span className="ml-1 font-semibold">{delegate.mandateCount}</span>
                      </Badge>
                      <Badge variant="ghost">
                        Последняя активность: {new Date(delegate.lastActive).toLocaleDateString()}
                      </Badge>
                    </div>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </ScrollArea>
      </CardContent>
    </Card>
  );
};

export default DelegateListWidget;
