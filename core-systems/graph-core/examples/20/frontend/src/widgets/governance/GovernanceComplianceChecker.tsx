// src/widgets/Governance/GovernanceComplianceChecker.tsx

import React from 'react';
import { useGovernanceCompliance } from '@/hooks/governance/useGovernanceCompliance';
import { Card, CardContent } from '@/components/ui/card';
import { ShieldAlert, CheckCheck, HelpCircle } from 'lucide-react';
import { TooltipProvider, Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { Progress } from '@/components/ui/progress';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';

interface GovernanceComplianceCheckerProps {
  proposalId: string;
}

const GovernanceComplianceChecker: React.FC<GovernanceComplianceCheckerProps> = ({ proposalId }) => {
  const { isLoading, error, complianceReport } = useGovernanceCompliance(proposalId);

  if (isLoading) {
    return (
      <Card className="p-4">
        <CardContent className="text-sm text-muted-foreground">
          Проверка соответствия уставу...
        </CardContent>
      </Card>
    );
  }

  if (error || !complianceReport) {
    return (
      <Card className="p-4 border border-destructive/40 bg-destructive/10">
        <CardContent className="flex items-center gap-2 text-destructive text-sm">
          <ShieldAlert size={18} /> Не удалось выполнить анализ соответствия.
        </CardContent>
      </Card>
    );
  }

  const {
    complianceScore,        // 0 - 100
    ethicalFlags,           // string[]
    policyViolations,       // string[]
    legalConflicts,         // string[]
    clauseRefs,             // string[] (["Art.4.3", "Code.E-2"])
    zeroTrustCheck,         // boolean
    auditReady,             // boolean
    aiComments,             // string[]
  } = complianceReport;

  const scoreColor =
    complianceScore > 85 ? 'text-green-600' :
    complianceScore > 60 ? 'text-yellow-600' : 'text-red-600';

  return (
    <Card className="border border-border p-4 rounded-xl bg-background/80 shadow-md">
      <CardContent className="space-y-4">
        <div className="flex justify-between items-center">
          <div>
            <h4 className="text-sm font-semibold text-muted-foreground">Соответствие уставу DAO</h4>
            <p className={cn('text-2xl font-bold', scoreColor)}>{complianceScore.toFixed(1)}%</p>
          </div>
          <div className="flex items-center gap-2">
            {complianceScore >= 85 ? (
              <CheckCheck className="text-green-500" size={24} />
            ) : (
              <ShieldAlert className="text-yellow-500" size={24} />
            )}
            <span className={cn('text-sm font-medium', scoreColor)}>
              {complianceScore >= 85
                ? 'Устав соблюдён'
                : complianceScore >= 60
                ? 'Требуется ревью'
                : 'Конфликт с уставом'}
            </span>
          </div>
        </div>

        <Progress value={complianceScore} className="h-2" />

        <div className="grid grid-cols-2 gap-4 text-sm">
          <div className="flex items-center gap-2">
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <HelpCircle size={16} className="text-muted-foreground cursor-help" />
                </TooltipTrigger>
                <TooltipContent>
                  Список флагов, поднятых этическим ядром
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
            Этические флаги:
          </div>
          <div className="flex flex-wrap gap-2">
            {ethicalFlags.length === 0 ? (
              <Badge variant="success">Нет</Badge>
            ) : (
              ethicalFlags.map((f, i) => <Badge key={i} variant="warning">{f}</Badge>)
            )}
          </div>

          <div className="flex items-center gap-2">
            Нарушения политики DAO:
          </div>
          <div className="flex flex-wrap gap-2">
            {policyViolations.length === 0 ? (
              <Badge variant="success">Нет</Badge>
            ) : (
              policyViolations.map((p, i) => <Badge key={i} variant="destructive">{p}</Badge>)
            )}
          </div>

          <div className="flex items-center gap-2">
            Юридические конфликты:
          </div>
          <div className="flex flex-wrap gap-2">
            {legalConflicts.length === 0 ? (
              <Badge variant="success">Нет</Badge>
            ) : (
              legalConflicts.map((l, i) => <Badge key={i} variant="outline">{l}</Badge>)
            )}
          </div>

          <div className="flex items-center gap-2">
            Проверка Zero Trust:
          </div>
          <Badge variant={zeroTrustCheck ? 'success' : 'destructive'}>
            {zeroTrustCheck ? 'Пройдена' : 'Не пройдена'}
          </Badge>

          <div className="flex items-center gap-2">
            Аудиторская готовность:
          </div>
          <Badge variant={auditReady ? 'success' : 'warning'}>
            {auditReady ? 'Готов к аудиту' : 'Требует подготовки'}
          </Badge>
        </div>

        {clauseRefs.length > 0 && (
          <div>
            <h5 className="text-sm font-medium text-foreground mt-4 mb-1">Нарушенные положения:</h5>
            <ul className="list-disc list-inside text-sm text-muted-foreground space-y-1">
              {clauseRefs.map((ref, idx) => (
                <li key={idx}>{ref}</li>
              ))}
            </ul>
          </div>
        )}

        {aiComments.length > 0 && (
          <div>
            <h5 className="text-sm font-medium text-foreground mt-4 mb-1">Комментарии AI:</h5>
            <ul className="list-disc list-inside text-sm text-muted-foreground space-y-1">
              {aiComments.map((text, i) => (
                <li key={i}>{text}</li>
              ))}
            </ul>
          </div>
        )}
      </CardContent>
    </Card>
  );
};

export default GovernanceComplianceChecker;
