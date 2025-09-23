// src/widgets/Governance/ConstitutionReferencePanel.tsx

import React, { useEffect, useState } from 'react';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Skeleton } from '@/components/ui/skeleton';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';
import { BookOpenIcon, SearchIcon, ShieldCheckIcon, HistoryIcon } from '@/components/icons';
import { useDebounce } from '@/hooks/useDebounce';
import { fetchConstitutionArticles } from '@/services/governance/constitutionService';
import type { ConstitutionArticle } from '@/types/governance';

interface ConstitutionReferencePanelProps {
  highlightKeywords?: string[];
  allowSearch?: boolean;
  maxHeight?: number;
}

export const ConstitutionReferencePanel: React.FC<ConstitutionReferencePanelProps> = ({
  highlightKeywords = [],
  allowSearch = true,
  maxHeight = 420
}) => {
  const [articles, setArticles] = useState<ConstitutionArticle[]>([]);
  const [filtered, setFiltered] = useState<ConstitutionArticle[]>([]);
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(true);
  const debouncedQuery = useDebounce(query, 300);

  useEffect(() => {
    setLoading(true);
    fetchConstitutionArticles()
      .then((data) => {
        setArticles(data);
        setFiltered(data);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  useEffect(() => {
    if (!debouncedQuery) {
      setFiltered(articles);
      return;
    }

    const lower = debouncedQuery.toLowerCase();
    const filteredList = articles.filter((a) =>
      a.title.toLowerCase().includes(lower) ||
      a.content.toLowerCase().includes(lower)
    );
    setFiltered(filteredList);
  }, [debouncedQuery, articles]);

  return (
    <div
      className={cn(
        'border rounded-md shadow-md bg-background p-4 flex flex-col gap-4',
        `max-h-[${maxHeight}px]`
      )}
      role="region"
      aria-label="Свод положений DAO"
    >
      <div className="flex items-center justify-between gap-3">
        <div className="text-base font-semibold flex items-center gap-2">
          <BookOpenIcon className="w-4 h-4 text-muted-foreground" />
          Свод DAO-положений
        </div>
        <Badge variant="outline" className="text-xs px-2 py-0.5 tracking-wide uppercase">
          v1.3.7-ethics
        </Badge>
      </div>

      {allowSearch && (
        <div className="relative">
          <SearchIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Поиск по заголовкам или содержанию..."
            className="pl-10"
          />
        </div>
      )}

      <ScrollArea className="flex-1 pr-2">
        {loading ? (
          <div className="space-y-3">
            <Skeleton className="h-4 w-5/6" />
            <Skeleton className="h-4 w-2/3" />
            <Skeleton className="h-4 w-3/4" />
          </div>
        ) : (
          <ul className="flex flex-col gap-3">
            {filtered.map((article, idx) => (
              <li key={article.id} className="bg-muted/30 rounded-md p-3 shadow-sm transition hover:bg-muted/50">
                <div className="flex justify-between items-center">
                  <div className="font-medium text-sm text-foreground/90">
                    {idx + 1}. {article.title}
                  </div>
                  {article.immutable && (
                    <ShieldCheckIcon className="w-4 h-4 text-green-500" title="Защищено от изменений" />
                  )}
                </div>
                <div className="text-xs text-muted-foreground mt-1 leading-snug whitespace-pre-wrap">
                  {highlightKeywords.length > 0
                    ? highlightText(article.content, highlightKeywords)
                    : article.content}
                </div>
              </li>
            ))}
            {filtered.length === 0 && (
              <div className="text-sm text-muted-foreground italic">Ничего не найдено.</div>
            )}
          </ul>
        )}
      </ScrollArea>

      <div className="flex justify-end">
        <button
          className="inline-flex items-center gap-2 text-xs text-muted-foreground hover:text-primary transition"
          aria-label="Открыть историю версий"
        >
          <HistoryIcon className="w-4 h-4" />
          История версий
        </button>
      </div>
    </div>
  );
};

// Вспомогательная функция для подсветки текста
function highlightText(text: string, keywords: string[]): React.ReactNode {
  const regex = new RegExp(`(${keywords.join('|')})`, 'gi');
  const parts = text.split(regex);
  return parts.map((part, i) =>
    regex.test(part) ? (
      <mark key={i} className="bg-yellow-200 text-foreground px-1 rounded-sm">
        {part}
      </mark>
    ) : (
      <span key={i}>{part}</span>
    )
  );
}
