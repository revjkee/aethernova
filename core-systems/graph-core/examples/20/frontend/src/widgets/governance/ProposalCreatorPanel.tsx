// src/widgets/Governance/ProposalCreatorPanel.tsx

import React, { useState, useEffect } from 'react';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Button } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Card, CardContent } from '@/components/ui/card';
import { useCreateProposal } from '@/hooks/governance/useCreateProposal';
import { useProposalHints } from '@/hooks/ai/useProposalHints';
import { Loader2, Sparkles, Send, ShieldCheck } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Tooltip, TooltipContent, TooltipTrigger, TooltipProvider } from '@/components/ui/tooltip';

const CATEGORY_OPTIONS = [
  'Обновление DAO',
  'Изменение токеномики',
  'Этическое исключение',
  'Назначение роли',
  'Финансирование',
  'Законопроект',
  'Прочее',
];

const PHASE_OPTIONS = [
  'Предложение (Draft)',
  'Открытие (Open)',
  'Голосование (Voting)',
  'Внедрение (Execution)',
];

const ProposalCreatorPanel = () => {
  const [title, setTitle] = useState('');
  const [summary, setSummary] = useState('');
  const [category, setCategory] = useState('');
  const [phase, setPhase] = useState('Предложение (Draft)');
  const [aiHint, setAiHint] = useState('');
  const [preview, setPreview] = useState('');
  const [legalVerified, setLegalVerified] = useState(false);

  const { createProposal, isCreating, success } = useCreateProposal();
  const { loadingHint, getAiHint } = useProposalHints();

  const handleGenerateHint = async () => {
    const hint = await getAiHint({ title, summary, category });
    setAiHint(hint);
  };

  const handleSubmit = async () => {
    const proposal = {
      title,
      summary,
      category,
      phase,
      aiHint,
      legalVerified,
      preview,
    };
    await createProposal(proposal);
  };

  useEffect(() => {
    if (title && summary) {
      const draft = `# ${title}\n\n${summary}\n\n## Категория\n${category}\n\n## Фаза\n${phase}\n\n---\nПредложение подготовлено участником DAO.`;
      setPreview(draft);
    }
  }, [title, summary, category, phase]);

  return (
    <Card className="p-6 shadow-md border border-muted rounded-2xl bg-background/90 space-y-6">
      <CardContent className="space-y-4">
        <div>
          <label className="block text-sm font-medium mb-1 text-muted-foreground">Заголовок предложения</label>
          <Input
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="Добавить модуль голосования ZK-сети"
          />
        </div>

        <div>
          <label className="block text-sm font-medium mb-1 text-muted-foreground">Краткое описание / цель</label>
          <Textarea
            rows={4}
            value={summary}
            onChange={(e) => setSummary(e.target.value)}
            placeholder="Что конкретно предлагается, какова цель и ожидаемый эффект?"
          />
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium mb-1 text-muted-foreground">Категория</label>
            <Select value={category} onValueChange={setCategory}>
              <SelectTrigger>
                <SelectValue placeholder="Выберите категорию" />
              </SelectTrigger>
              <SelectContent>
                {CATEGORY_OPTIONS.map((opt) => (
                  <SelectItem key={opt} value={opt}>
                    {opt}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div>
            <label className="block text-sm font-medium mb-1 text-muted-foreground">Фаза предложения</label>
            <Select value={phase} onValueChange={setPhase}>
              <SelectTrigger>
                <SelectValue placeholder="Выберите фазу" />
              </SelectTrigger>
              <SelectContent>
                {PHASE_OPTIONS.map((opt) => (
                  <SelectItem key={opt} value={opt}>
                    {opt}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <TooltipProvider>
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="ghost"
                  size="sm"
                  disabled={loadingHint}
                  onClick={handleGenerateHint}
                >
                  <Sparkles className="mr-2 h-4 w-4" />
                  AI-хинт
                </Button>
              </TooltipTrigger>
              <TooltipContent>
                Генерация краткой AI-оценки или уточнения для предложения
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
          {loadingHint && <Loader2 className="animate-spin text-muted-foreground h-4 w-4" />}
        </div>

        {aiHint && (
          <div className="bg-muted/30 p-4 rounded-lg text-sm text-muted-foreground border-l-4 border-accent">
            <p className="mb-1 font-medium text-accent-foreground">AI-хинт:</p>
            <p>{aiHint}</p>
          </div>
        )}

        <div className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={legalVerified}
            onChange={() => setLegalVerified((v) => !v)}
            className="scale-110 accent-green-500"
          />
          <label className="text-sm text-muted-foreground">Подтверждаю соответствие уставу и закону</label>
          <ShieldCheck className="text-green-500" size={16} />
        </div>

        <div className="mt-6">
          <h4 className="text-sm font-medium text-muted-foreground mb-1">Предпросмотр:</h4>
          <pre className="bg-muted/20 p-4 rounded-lg text-xs overflow-auto text-muted-foreground border border-muted">
            {preview}
          </pre>
        </div>

        <div className="mt-6 flex justify-end">
          <Button
            disabled={!title || !summary || !category || isCreating}
            onClick={handleSubmit}
          >
            {isCreating ? (
              <Loader2 className="animate-spin mr-2 h-4 w-4" />
            ) : (
              <Send className="mr-2 h-4 w-4" />
            )}
            Создать предложение
          </Button>
        </div>

        {success && (
          <div className="text-sm text-green-600 mt-2">
            ✔ Предложение успешно создано
          </div>
        )}
      </CardContent>
    </Card>
  );
};

export default ProposalCreatorPanel;
