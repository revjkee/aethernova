// src/widgets/Governance/GovernanceActionLog.tsx

import React, { useState, useEffect } from 'react';
import {
  Card,
  CardHeader,
  CardContent,
} from '@/components/ui/card';
import { Table, TableHead, TableRow, TableHeaderCell, TableCell, TableBody } from '@/components/ui/table';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { fetchGovernanceLog } from '@/services/governance/actionLogService';
import { LogEvent } from '@/types/governance';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Skeleton } from '@/components/ui/skeleton';
import { cn } from '@/lib/utils';
import { ZkShieldIcon, SignatureIcon, UserIcon } from '@/components/icons';
import { Tooltip, TooltipTrigger, TooltipContent } from '@/components/ui/tooltip';

const FILTER_PHASES = ['proposal', 'voting', 'execution', 'emergency', 'revocation'];
const FILTER_RESULTS = ['success', 'failed', 'pending', 'reverted'];

export default function GovernanceActionLog() {
  const [log, setLog] = useState<LogEvent[]>([]);
  const [search, setSearch] = useState('');
  const [phase, setPhase] = useState<string | null>(null);
  const [result, setResult] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const loadLog = async () => {
      setLoading(true);
      const data = await fetchGovernanceLog();
      setLog(data);
      setLoading(false);
    };
    loadLog();
  }, []);

  const filtered = log.filter(entry => {
    const matchSearch =
      entry.actor.toLowerCase().includes(search.toLowerCase()) ||
      entry.action.toLowerCase().includes(search.toLowerCase()) ||
      entry.details.toLowerCase().includes(search.toLowerCase());
    const matchPhase = phase ? entry.phase === phase : true;
    const matchResult = result ? entry.result === result : true;
    return matchSearch && matchPhase && matchResult;
  });

  return (
    <Card className="p-6 w-full rounded-2xl border shadow-sm bg-background">
      <CardHeader className="text-lg font-semibold mb-4 text-primary">
        Журнал действий управления
      </CardHeader>

      <CardContent className="space-y-4">
        <div className="flex flex-col md:flex-row gap-4">
          <Input
            placeholder="Поиск по делегату или действию..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="flex-1"
          />
          <Select onValueChange={setPhase}>
            <SelectTrigger>
              <SelectValue placeholder="Фаза" />
            </SelectTrigger>
            <SelectContent>
              {FILTER_PHASES.map(p => (
                <SelectItem key={p} value={p}>{p}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select onValueChange={setResult}>
            <SelectTrigger>
              <SelectValue placeholder="Результат" />
            </SelectTrigger>
            <SelectContent>
              {FILTER_RESULTS.map(r => (
                <SelectItem key={r} value={r}>{r}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <ScrollArea className="h-[550px] rounded-md border bg-muted">
          <Table>
            <TableHead>
              <TableRow>
                <TableHeaderCell>Время</TableHeaderCell>
                <TableHeaderCell>Актор</TableHeaderCell>
                <TableHeaderCell>Действие</TableHeaderCell>
                <TableHeaderCell>Фаза</TableHeaderCell>
                <TableHeaderCell>Результат</TableHeaderCell>
                <TableHeaderCell className="text-right">Интеграции</TableHeaderCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {loading ? (
                [...Array(10)].map((_, i) => (
                  <TableRow key={i}>
                    <TableCell><Skeleton className="h-4 w-20" /></TableCell>
                    <TableCell><Skeleton className="h-4 w-24" /></TableCell>
                    <TableCell><Skeleton className="h-4 w-36" /></TableCell>
                    <TableCell><Skeleton className="h-4 w-16" /></TableCell>
                    <TableCell><Skeleton className="h-4 w-16" /></TableCell>
                    <TableCell className="text-right"><Skeleton className="h-4 w-24" /></TableCell>
                  </TableRow>
                ))
              ) : (
                filtered.map((entry, idx) => (
                  <TableRow key={idx}>
                    <TableCell>{new Date(entry.timestamp).toLocaleString()}</TableCell>
                    <TableCell className="flex items-center gap-2">
                      <UserIcon className="w-4 h-4" />
                      <span>{entry.actor}</span>
                    </TableCell>
                    <TableCell>{entry.action}</TableCell>
                    <TableCell>
                      <Badge variant="secondary">{entry.phase}</Badge>
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={
                          entry.result === 'success'
                            ? 'success'
                            : entry.result === 'failed'
                            ? 'destructive'
                            : entry.result === 'pending'
                            ? 'warning'
                            : 'secondary'
                        }
                      >
                        {entry.result}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right space-x-2">
                      {entry.zkVerified && (
                        <Tooltip>
                          <TooltipTrigger>
                            <ZkShieldIcon className="text-green-500 w-5 h-5" />
                          </TooltipTrigger>
                          <TooltipContent>Zero-Knowledge подтверждение</TooltipContent>
                        </Tooltip>
                      )}
                      {entry.signature && (
                        <Tooltip>
                          <TooltipTrigger>
                            <SignatureIcon className="text-blue-500 w-5 h-5" />
                          </TooltipTrigger>
                          <TooltipContent>Подпись {entry.signature.slice(0, 10)}...</TooltipContent>
                        </Tooltip>
                      )}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </ScrollArea>
      </CardContent>
    </Card>
  );
}
