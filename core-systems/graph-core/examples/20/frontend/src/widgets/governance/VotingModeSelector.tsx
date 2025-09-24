// src/widgets/Governance/VotingModeSelector.tsx

import React, { useState, useEffect } from 'react';
import { ToggleGroup, ToggleGroupItem } from '@/components/ui/toggle-group';
import { Badge } from '@/components/ui/badge';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { cn } from '@/lib/utils';
import {
  UserCheckIcon,
  BotIcon,
  UsersIcon,
  ShieldCheckIcon
} from '@/components/icons';
import { useGovernanceContext } from '@/context/GovernanceProvider';
import { VotingMode } from '@/types/governance';
import { logInteraction } from '@/lib/logging';

interface VotingModeSelectorProps {
  defaultMode?: VotingMode;
  onChange?: (mode: VotingMode) => void;
  disabledModes?: VotingMode[];
  readonly?: boolean;
}

const modeDescriptions: Record<VotingMode, string> = {
  individual: 'Личное голосование. Решения принимаются вами.',
  delegate: 'Вы голосуете через делегата, которому вы доверяете.',
  ai: 'Голосование осуществляется ИИ-ассистентом на основе ваших предпочтений.'
};

const icons: Record<VotingMode, JSX.Element> = {
  individual: <UserCheckIcon className="w-4 h-4 mr-1" />,
  delegate: <UsersIcon className="w-4 h-4 mr-1" />,
  ai: <BotIcon className="w-4 h-4 mr-1" />
};

const modeLabels: Record<VotingMode, string> = {
  individual: 'Сам',
  delegate: 'Делегат',
  ai: 'ИИ'
};

export const VotingModeSelector: React.FC<VotingModeSelectorProps> = ({
  defaultMode = 'individual',
  onChange,
  disabledModes = [],
  readonly = false
}) => {
  const [mode, setMode] = useState<VotingMode>(defaultMode);
  const { updateVotingMode } = useGovernanceContext();

  useEffect(() => {
    updateVotingMode(mode);
    if (onChange) onChange(mode);
    logInteraction('voting_mode_change', { mode });
  }, [mode, onChange, updateVotingMode]);

  return (
    <div className="flex flex-col gap-2" role="radiogroup" aria-label="Выбор режима голосования">
      <div className="text-sm font-semibold flex items-center gap-2">
        <ShieldCheckIcon className="w-4 h-4 text-muted-foreground" />
        Режим голосования:
        <Badge variant="outline" className="text-xs px-2 py-0.5 uppercase tracking-wider">
          {mode.toUpperCase()}
        </Badge>
      </div>
      <ToggleGroup
        type="single"
        value={mode}
        onValueChange={(val: VotingMode) => {
          if (val && !readonly && !disabledModes.includes(val)) {
            setMode(val);
          }
        }}
        className="flex gap-2"
      >
        {(['individual', 'delegate', 'ai'] as VotingMode[]).map((m) => (
          <Tooltip key={m}>
            <TooltipTrigger asChild>
              <ToggleGroupItem
                value={m}
                disabled={readonly || disabledModes.includes(m)}
                aria-label={`Выбрать режим: ${modeLabels[m]}`}
                className={cn(
                  'flex items-center px-3 py-1.5 text-sm rounded-md border border-input shadow-sm',
                  mode === m && 'bg-primary text-white hover:bg-primary/90',
                  readonly && 'cursor-not-allowed opacity-50'
                )}
              >
                {icons[m]}
                {modeLabels[m]}
              </ToggleGroupItem>
            </TooltipTrigger>
            <TooltipContent>{modeDescriptions[m]}</TooltipContent>
          </Tooltip>
        ))}
      </ToggleGroup>
    </div>
  );
};
