import React, { useEffect, useState, useMemo, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useDebounce } from "@/hooks/utils/useDebounce";
import { usePrivacyPolicy } from "@/hooks/privacy/usePrivacyPolicy";
import { PolicyVersion, PolicyClause } from "@/types/privacy";
import { Highlighter } from "@/components/shared/Highlighter";
import { motion } from "framer-motion";
import { BookText, Search, HistoryIcon } from "lucide-react";

const highlightTerms = ["tracking", "retention", "profiling", "3rd party", "data transfer", "biometric", "consent"];

export const PrivacyPolicyReader: React.FC = () => {
  const [searchQuery, setSearchQuery] = useState("");
  const debouncedSearch = useDebounce(searchQuery, 300);

  const { versions, loading, error } = usePrivacyPolicy();
  const latestVersion = useMemo(() => versions?.[0] ?? null, [versions]);

  const filteredClauses = useMemo(() => {
    if (!latestVersion) return [];
    if (!debouncedSearch) return latestVersion.clauses;

    return latestVersion.clauses.filter((clause: PolicyClause) =>
      clause.text.toLowerCase().includes(debouncedSearch.toLowerCase())
    );
  }, [debouncedSearch, latestVersion]);

  const renderClause = useCallback(
    (clause: PolicyClause, index: number) => {
      const highlighted = <Highlighter text={clause.text} keywords={[debouncedSearch, ...highlightTerms]} />;
      return (
        <motion.div
          key={clause.id}
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: index * 0.02 }}
          className="mb-6 border-b pb-4"
        >
          <div className="flex items-center gap-2 mb-1 text-sm text-muted-foreground font-medium">
            <Badge variant="outline">#{clause.id}</Badge>
            <span>{clause.section}</span>
          </div>
          <div className="text-sm leading-relaxed">{highlighted}</div>
        </motion.div>
      );
    },
    [debouncedSearch]
  );

  return (
    <Card className="h-full w-full">
      <CardHeader className="flex flex-row items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <BookText className="w-5 h-5 text-blue-600" />
          <CardTitle className="text-lg font-semibold text-foreground">
            Политика конфиденциальности
          </CardTitle>
        </div>
        <div className="relative w-[360px]">
          <Search className="absolute left-3 top-2.5 w-4 h-4 text-muted-foreground" />
          <Input
            className="pl-9 pr-3"
            placeholder="Поиск по политике (например: 'tracking', 'retention')"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>
      </CardHeader>
      <CardContent className="h-full overflow-hidden">
        <div className="flex items-center gap-4 mb-3 text-xs text-muted-foreground">
          <HistoryIcon className="w-3 h-3" />
          <span>Текущая версия: {latestVersion?.version ?? "—"} от {latestVersion?.publishedAt ?? "—"}</span>
        </div>
        <ScrollArea className="h-[600px] pr-3">
          {loading && <p className="text-muted-foreground text-sm">Загрузка...</p>}
          {error && <p className="text-destructive text-sm">Ошибка загрузки политики.</p>}
          {!loading && !error && filteredClauses.map(renderClause)}
          {!loading && !error && filteredClauses.length === 0 && (
            <p className="text-sm text-muted-foreground">Совпадений не найдено по запросу: <strong>{searchQuery}</strong></p>
          )}
        </ScrollArea>
      </CardContent>
    </Card>
  );
};

PrivacyPolicyReader.displayName = "PrivacyPolicyReader";
