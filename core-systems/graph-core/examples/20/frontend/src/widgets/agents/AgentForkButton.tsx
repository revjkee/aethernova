import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Label } from '@/components/ui/label';
import { Input } from '@/components/ui/input';
import { Switch } from '@/components/ui/switch';
import { toast } from '@/shared/lib/toast';
import { forkAgent } from '@/shared/api/agentAPI';
import { validateIntentSet } from '@/shared/lib/agentValidators';
import { IconCopy, IconShieldCheck, IconSparkles } from 'lucide-react';
import { Spinner } from '@/shared/components/Spinner';

interface AgentForkButtonProps {
  agentId: string;
  currentName: string;
  onForked?: (newAgentId: string) => void;
}

export const AgentForkButton: React.FC<AgentForkButtonProps> = ({
  agentId,
  currentName,
  onForked,
}) => {
  const [open, setOpen] = useState(false);
  const [forkName, setForkName] = useState(`${currentName}_fork`);
  const [includeMemory, setIncludeMemory] = useState(true);
  const [includePersona, setIncludePersona] = useState(true);
  const [includeIntentGraph, setIncludeIntentGraph] = useState(true);
  const [loading, setLoading] = useState(false);

  const handleFork = async () => {
    setLoading(true);
    try {
      const forkData = {
        newName: forkName.trim(),
        cloneMemory: includeMemory,
        clonePersona: includePersona,
        cloneIntentGraph: includeIntentGraph,
      };

      if (!validateIntentSet(forkData)) {
        toast.error('Ошибка в структуре намерений агента');
        setLoading(false);
        return;
      }

      const newId = await forkAgent(agentId, forkData);
      toast.success(`Агент успешно форкнут: ${forkName}`);
      setOpen(false);
      if (onForked) onForked(newId);
    } catch (err) {
      toast.error('Не удалось форкнуть агента');
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <Button variant="outline" onClick={() => setOpen(true)}>
        <IconCopy size={16} className="mr-1" />
        Форк
      </Button>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>
              Клонировать агента <strong>{currentName}</strong>
            </DialogTitle>
          </DialogHeader>

          <div className="space-y-4">
            <Label>Имя нового агента</Label>
            <Input value={forkName} onChange={(e) => setForkName(e.target.value)} />

            <div className="flex items-center justify-between">
              <Label>Копировать память</Label>
              <Switch checked={includeMemory} onCheckedChange={setIncludeMemory} />
            </div>

            <div className="flex items-center justify-between">
              <Label>Копировать личность</Label>
              <Switch checked={includePersona} onCheckedChange={setIncludePersona} />
            </div>

            <div className="flex items-center justify-between">
              <Label>Копировать граф намерений</Label>
              <Switch checked={includeIntentGraph} onCheckedChange={setIncludeIntentGraph} />
            </div>

            {loading && <Spinner label="Клонирование агента..." />}
          </div>

          <DialogFooter className="mt-4">
            <Button variant="ghost" onClick={() => setOpen(false)}>
              Отмена
            </Button>
            <Button onClick={handleFork} disabled={loading}>
              <IconShieldCheck size={16} className="mr-1" />
              Подтвердить форк
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
};
