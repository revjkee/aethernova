import React, { useEffect, useState, useCallback } from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { Label } from '@/components/ui/label';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { toast } from '@/shared/lib/toast';
import { usePersonaAPI } from '@/shared/api/hooks/usePersonaAPI';
import { useAutoSave } from '@/shared/hooks/useAutoSave';
import { formatTimestamp } from '@/shared/utils/dateUtils';
import { Spinner } from '@/shared/components/Spinner';
import './styles/AgentPersonaEditor.css';

interface AgentPersonaEditorProps {
  agentId: string;
}

interface PersonaSlot {
  id: string;
  title: string;
  content: string;
  lastUpdated: number;
}

export const AgentPersonaEditor: React.FC<AgentPersonaEditorProps> = ({ agentId }) => {
  const [slots, setSlots] = useState<PersonaSlot[]>([]);
  const [selected, setSelected] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(true);
  const { fetchPersona, updatePersona } = usePersonaAPI(agentId);

  const loadPersona = useCallback(async () => {
    setLoading(true);
    try {
      const data = await fetchPersona();
      setSlots(data);
      if (data.length > 0) setSelected(data[0].id);
    } catch {
      toast.error('Ошибка при загрузке личности агента');
    } finally {
      setLoading(false);
    }
  }, [agentId]);

  useEffect(() => {
    loadPersona();
  }, [loadPersona]);

  const handleChange = (id: string, value: string) => {
    setSlots((prev) =>
      prev.map((slot) =>
        slot.id === id ? { ...slot, content: value, lastUpdated: Date.now() } : slot
      )
    );
  };

  const { triggerSave, saving } = useAutoSave({
    data: slots,
    saveCallback: async (updated) => {
      await updatePersona(updated);
      toast.success('Личность агента обновлена');
    },
    debounceMs: 1000,
  });

  const handleManualSave = () => triggerSave();

  if (loading) return <Spinner label="Загрузка личности..." />;

  return (
    <Card className="persona-editor">
      <CardContent>
        <Tabs value={selected} onValueChange={setSelected}>
          <TabsList>
            {slots.map((slot) => (
              <TabsTrigger key={slot.id} value={slot.id}>
                {slot.title}
              </TabsTrigger>
            ))}
          </TabsList>
          {slots.map((slot) => (
            <TabsContent key={slot.id} value={slot.id}>
              <div className="persona-slot">
                <Label className="persona-label">Слот: {slot.title}</Label>
                <Textarea
                  value={slot.content}
                  onChange={(e) => handleChange(slot.id, e.target.value)}
                  onBlur={handleManualSave}
                  className="persona-textarea"
                  rows={8}
                />
                <div className="persona-footer">
                  Последнее обновление: {formatTimestamp(slot.lastUpdated)}
                  {saving && <span className="saving-indicator">Сохранение...</span>}
                </div>
              </div>
            </TabsContent>
          ))}
        </Tabs>
      </CardContent>
    </Card>
  );
