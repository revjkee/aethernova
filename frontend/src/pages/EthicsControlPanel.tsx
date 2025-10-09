// frontend/src/pages/EthicsControlPanel.tsx

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { z } from "zod";

import {
  Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Separator } from "@/components/ui/separator";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Progress } from "@/components/ui/progress";

import {
  ShieldCheck, Settings2, Plus, Save, RefreshCcw, Search, ScanLine,
  Copy, Download, UploadCloud, Trash2, Edit3, CheckCircle2, XCircle,
  Filter, ListChecks, History, GitBranch, Hash as HashIcon, Layers3,
  Info, CheckSquare, Square, Spline, AlertTriangle, CopyCheck, CopyX
} from "lucide-react";

// -------------------------------- Types --------------------------------

type RiskCategory =
  | "privacy"
  | "bias"
  | "toxicity"
  | "selfharm"
  | "medical"
  | "legal"
  | "copyright"
  | "violence"
  | "politics"
  | "safety";

type RuleSeverity = "low" | "medium" | "high" | "critical";

type Rule = {
  id: string;
  title: string;
  description: string;
  category: RiskCategory;
  severity: RuleSeverity;
  pattern?: string; // JS RegExp (строка)
  hint?: string;
  enabled: boolean;
};

type Policy = { rules: Rule[] };

type VersionSnapshot = {
  id: string;
  createdAt: string; // ISO
  hash: string;
  rulesCount: number;
  enabledCount: number;
  policy: Policy;
};

const CATEGORIES: { value: RiskCategory; label: string }[] = [
  { value: "privacy", label: "Приватность" },
  { value: "bias", label: "Предвзятость" },
  { value: "toxicity", label: "Токсичность" },
  { value: "selfharm", label: "Самоповреждение" },
  { value: "medical", label: "Медицина" },
  { value: "legal", label: "Юридическое" },
  { value: "copyright", label: "Авторское право" },
  { value: "violence", label: "Насилие/Оружие" },
  { value: "politics", label: "Политика" },
  { value: "safety", label: "Безопасность" },
];

const SEVERITIES: { value: RuleSeverity; label: string }[] = [
  { value: "low", label: "Низкая" },
  { value: "medium", label: "Средняя" },
  { value: "high", label: "Высокая" },
  { value: "critical", label: "Критическая" },
];

// -------------------------------- Schemas --------------------------------

const ruleSchema = z.object({
  id: z.string().min(1),
  title: z.string().min(3, "Название слишком короткое"),
  description: z.string().min(3, "Описание слишком короткое"),
  category: z.custom<RiskCategory>(),
  severity: z.custom<RuleSeverity>(),
  pattern: z.string().optional(),
  hint: z.string().optional(),
  enabled: z.boolean(),
});

const policySchema = z.object({ rules: z.array(ruleSchema) });

// -------------------------------- Defaults --------------------------------

const DEFAULT_RULES: Rule[] = [
  {
    id: "tox-001",
    title: "Ненормативная лексика/оскорбления",
    description: "Выявление токсичной или уничижительной лексики.",
    category: "toxicity",
    severity: "medium",
    pattern: "\\b(дурак|идиот|туп(ой|ица))\\b",
    hint: "Смягчить язык, переформулировать.",
    enabled: true,
  },
  {
    id: "bias-001",
    title: "Стереотипы по социальным признакам",
    description: "Общие утверждения о группах без доказательств.",
    category: "bias",
    severity: "high",
    pattern: "\\b(все|кажды(e|й|йе))\\s+(женщины|мужчины|иностранцы|мигранты)\\b",
    hint: "Уточнить формулировку, добавить источники.",
    enabled: true,
  },
  {
    id: "privacy-001",
    title: "Прямая утечка персональных данных",
    description: "Похоже на публикацию ПДн: телефон, адрес, e-mail.",
    category: "privacy",
    severity: "critical",
    pattern: "([+]?\\d{1,3}[\\s-]?)?\\(?\\d{3}\\)?[\\s-]?\\d{3}[\\s-]?\\d{2}[\\s-]?\\d{2}|\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b",
    hint: "Скрыть/обезличить данные, запросить согласие.",
    enabled: true,
  },
  {
    id: "copyright-001",
    title: "Вероятное нарушение авторских прав",
    description: "Запрос полного текста/песни/книги.",
    category: "copyright",
    severity: "medium",
    pattern: "\\b(полный текст|вся песня|вся глава|скачать книгу)\\b",
    hint: "Предложить краткую цитату или пересказ.",
    enabled: true,
  },
  {
    id: "medical-001",
    title: "Медицинские советы высокого риска",
    description: "Требуется дисклеймер/перенаправление к врачу.",
    category: "medical",
    severity: "high",
    pattern: "\\b(диагноз|лечить|рецепт|дозировка|антибиотик)\\b",
    hint: "Добавить дисклеймер, ссылку на клин. протоколы.",
    enabled: true,
  },
  {
    id: "legal-001",
    title: "Юридические рекомендации",
    description: "Требуется дисклеймер и ссылка на нормы.",
    category: "legal",
    severity: "medium",
    pattern: "\\b(договор|исковое|штраф|уголовн(ый|ое))\\b",
    hint: "Уточнить юрисдикцию, привести норму закона.",
    enabled: true,
  },
  {
    id: "violence-001",
    title: "Опасные инструкции",
    description: "Описание способов причинения вреда.",
    category: "violence",
    severity: "critical",
    pattern: "\\b(как\\s+сделать\\s+взрыв|яд|оружие)\\b",
    hint: "Отклонить, предложить безопасную альтернативу.",
    enabled: true,
  },
  {
    id: "politics-001",
    title: "Политическая агитация/дезинформация",
    description: "Утверждения без источников, агитация.",
    category: "politics",
    severity: "high",
    pattern: "\\b(голосуй\\s+за|все\\s+СМИ\\s+врут|фальсификац(ия|ии))\\b",
    hint: "Требуются проверяемые источники.",
    enabled: true,
  },
  {
    id: "safety-001",
    title: "Опасные бытовые советы",
    description: "Может привести к травмам/ущербу.",
    category: "safety",
    severity: "high",
    pattern: "\\b(без\\s+перчаток\\s+работай|пей\\s+бензин)\\b",
    hint: "Добавить инструкции по безопасности.",
    enabled: true,
  },
  {
    id: "selfharm-001",
    title: "Самоповреждение/суицидальные темы",
    description: "Контент, требующий деликатной эскалации.",
    category: "selfharm",
    severity: "critical",
    pattern: "\\b(покон(чить|чить)\\s+с\\s+собой|нанести\\s+вред)\\b",
    hint: "Поддержка, ресурсы помощи, без инструкций.",
    enabled: true,
  },
];

// -------------------------------- Utils --------------------------------

const LS_KEY = "ethics_policy_v1";
const LS_VERSIONS_KEY = "ethics_policy_versions_v1";

function nowISO() { return new Date().toISOString(); }

function makeHash(s: string): string {
  // Небезопасный (не крипто) хэш для видимой метки целостности
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h << 5) - h + s.charCodeAt(i);
  return `h${(h >>> 0).toString(16)}`;
}

function short(s?: string, head = 8, tail = 6) {
  if (!s) return "—";
  if (s.length <= head + tail + 3) return s;
  return `${s.slice(0, head)}...${s.slice(-tail)}`;
}

function safeRegex(pattern?: string): RegExp | null {
  if (!pattern) return null;
  try { return new RegExp(pattern, "gi"); } catch { return null; }
}

function genId(prefix = "rule"): string {
  return `${prefix}-${Math.random().toString(36).slice(2, 8)}`;
}

// -------------------------------- Component --------------------------------

const EthicsControlPanel: React.FC = () => {
  // загрузка политики
  const [policy, setPolicy] = useState<Policy>(() => {
    try {
      const raw = localStorage.getItem(LS_KEY);
      if (raw) return policySchema.parse(JSON.parse(raw));
    } catch {/* ignore */}
    return { rules: DEFAULT_RULES };
  });

  const policyHash = useMemo(() => makeHash(JSON.stringify(policy.rules.map(r => ({ id: r.id, enabled: r.enabled })))), [policy]);

  // версии
  const [versions, setVersions] = useState<VersionSnapshot[]>(() => {
    try {
      const raw = localStorage.getItem(LS_VERSIONS_KEY);
      if (raw) return JSON.parse(raw) as VersionSnapshot[];
    } catch {/* ignore */}
    // инициализируем первой версией
    const snap: VersionSnapshot = {
      id: genId("v"),
      createdAt: nowISO(),
      hash: policyHash,
      rulesCount: policy.rules.length,
      enabledCount: policy.rules.filter(r => r.enabled).length,
      policy,
    };
    localStorage.setItem(LS_VERSIONS_KEY, JSON.stringify([snap]));
    return [snap];
  });

  // фильтры/поиск
  const [q, setQ] = useState("");
  const [cat, setCat] = useState<RiskCategory | "all">("all");
  const [sev, setSev] = useState<RuleSeverity | "all">("all");
  const [onlyEnabled, setOnlyEnabled] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [testerText, setTesterText] = useState("");

  // формы - новое правило
  const [newRule, setNewRule] = useState<Rule>({
    id: genId(),
    title: "",
    description: "",
    category: "toxicity",
    severity: "medium",
    pattern: "",
    hint: "",
    enabled: true,
  });
  const [newErrors, setNewErrors] = useState<Record<string, string>>({});
  const [newSaving, setNewSaving] = useState(false);

  const resetNew = useCallback((values?: Partial<Rule>) => {
    setNewRule({
      id: genId(),
      title: "",
      description: "",
      category: "toxicity",
      severity: "medium",
      pattern: "",
      hint: "",
      enabled: true,
      ...values,
    });
    setNewErrors({});
  }, []);

  const submitNew = useCallback((handler: (data: Rule) => void) => {
    return async () => {
      try {
        // Валидация
        const result = ruleSchema.safeParse(newRule);
        if (!result.success) {
          const errors: Record<string, string> = {};
          result.error.errors.forEach(err => {
            if (err.path.length > 0) {
              errors[err.path[0] as string] = err.message;
            }
          });
          setNewErrors(errors);
          return;
        }
        
        setNewErrors({});
        setNewSaving(true);
        await handler(result.data);
      } catch (error) {
        console.error("Form submission error:", error);
      } finally {
        setNewSaving(false);
      }
    };
  }, [newRule]);

  // форма редактирования
  const [editRule, setEditRule] = useState<Rule | null>(null);
  const [editErrors, setEditErrors] = useState<Record<string, string>>({});
  const [editSaving, setEditSaving] = useState(false);

  const resetEdit = useCallback((rule: Rule) => {
    setEditRule(rule);
    setEditErrors({});
  }, []);

  const submitEdit = useCallback((handler: (data: Rule) => void) => {
    return async () => {
      if (!editRule) return;
      
      try {
        // Валидация
        const result = ruleSchema.safeParse(editRule);
        if (!result.success) {
          const errors: Record<string, string> = {};
          result.error.errors.forEach(err => {
            if (err.path.length > 0) {
              errors[err.path[0] as string] = err.message;
            }
          });
          setEditErrors(errors);
          return;
        }
        
        setEditErrors({});
        setEditSaving(true);
        await handler(result.data);
      } catch (error) {
        console.error("Form submission error:", error);
      } finally {
        setEditSaving(false);
      }
    };
  }, [editRule]);

  // эффекты: автосейв
  useEffect(() => {
    localStorage.setItem(LS_KEY, JSON.stringify(policy));
  }, [policy]);

  useEffect(() => {
    localStorage.setItem(LS_VERSIONS_KEY, JSON.stringify(versions));
  }, [versions]);

  // вычисляемое: отфильтрованные правила
  const filtered = useMemo(() => {
    const text = q.trim().toLowerCase();
    return policy.rules.filter(r => {
      if (onlyEnabled && !r.enabled) return false;
      if (cat !== "all" && r.category !== cat) return false;
      if (sev !== "all" && r.severity !== sev) return false;
      if (!text) return true;
      return (
        r.title.toLowerCase().includes(text) ||
        r.description.toLowerCase().includes(text) ||
        (r.pattern || "").toLowerCase().includes(text) ||
        r.id.toLowerCase().includes(text)
      );
    });
  }, [policy, q, cat, sev, onlyEnabled]);

  // операции
  const pushVersion = useCallback((p: Policy) => {
    const snap: VersionSnapshot = {
      id: genId("v"),
      createdAt: nowISO(),
      hash: makeHash(JSON.stringify(p.rules.map(r => ({ id: r.id, enabled: r.enabled })))),
      rulesCount: p.rules.length,
      enabledCount: p.rules.filter(r => r.enabled).length,
      policy: p,
    };
    setVersions(v => [snap, ...v].slice(0, 50)); // максимум 50 снапшотов
  }, []);

  const addRule = useCallback((r: Rule) => {
    // проверка regex заранее
    if (r.pattern && !safeRegex(r.pattern)) {
      alert("Невалидный regex: проверьте синтаксис");
      return;
    }
    const next: Policy = { rules: [r, ...policy.rules] };
    setPolicy(next);
    pushVersion(next);
    resetNew({
      id: genId(),
      title: "",
      description: "",
      category: "toxicity",
      severity: "medium",
      pattern: "",
      hint: "",
      enabled: true,
    });
  }, [policy, pushVersion, resetNew]);

  const startEdit = useCallback((r: Rule) => {
    setEditingId(r.id);
    resetEdit(r);
  }, [resetEdit]);

  const saveEdit = useCallback((r: Rule) => {
    if (r.pattern && !safeRegex(r.pattern)) {
      alert("Невалидный regex: проверьте синтаксис");
      return;
    }
    const next: Policy = { rules: policy.rules.map(x => x.id === r.id ? r : x) };
    setPolicy(next);
    pushVersion(next);
    setEditingId(null);
  }, [policy, pushVersion]);

  const removeRule = useCallback((id: string) => {
    const next: Policy = { rules: policy.rules.filter(r => r.id !== id) };
    setPolicy(next);
    pushVersion(next);
  }, [policy, pushVersion]);

  const duplicateRule = useCallback((id: string) => {
    const src = policy.rules.find(r => r.id === id);
    if (!src) return;
    const copy: Rule = { ...src, id: genId("copy"), title: `${src.title} (копия)` };
    const next: Policy = { rules: [copy, ...policy.rules] };
    setPolicy(next);
    pushVersion(next);
  }, [policy, pushVersion]);

  const toggleRule = useCallback((id: string, enabled: boolean) => {
    const next: Policy = { rules: policy.rules.map(r => r.id === id ? { ...r, enabled } : r) };
    setPolicy(next);
  }, [policy]);

  const bulkToggleCategory = useCallback((category: RiskCategory, enabled: boolean) => {
    const next: Policy = { rules: policy.rules.map(r => r.category === category ? { ...r, enabled } : r) };
    setPolicy(next);
    pushVersion(next);
  }, [policy, pushVersion]);

  const bulkToggleAll = useCallback((enabled: boolean) => {
    const next: Policy = { rules: policy.rules.map(r => ({ ...r, enabled })) };
    setPolicy(next);
    pushVersion(next);
  }, [policy, pushVersion]);

  const resetDefaults = useCallback(() => {
    const next: Policy = { rules: DEFAULT_RULES };
    setPolicy(next);
    pushVersion(next);
  }, [pushVersion]);

  const revertTo = useCallback((vid: string) => {
    const v = versions.find(x => x.id === vid);
    if (!v) return;
    setPolicy(v.policy);
    // создаем новый снапшот-«возврат»
    pushVersion(v.policy);
  }, [versions, pushVersion]);

  // импорт/экспорт
  const [importText, setImportText] = useState(() => JSON.stringify({ rules: DEFAULT_RULES }, null, 2));
  const applyImport = useCallback(() => {
    try {
      const parsed = policySchema.parse(JSON.parse(importText));
      const next: Policy = parsed;
      setPolicy(next);
      pushVersion(next);
    } catch (e: any) {
      alert(e?.message || "Ошибка разбора JSON");
    }
  }, [importText, pushVersion]);

  const importFromFile = useCallback((file: File) => {
    const reader = new FileReader();
    reader.onload = () => { setImportText(String(reader.result || "")); };
    reader.readAsText(file);
  }, []);

  const exportPolicy = useCallback((p: Policy = policy) => {
    const blob = new Blob([JSON.stringify(p, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `ethics_policy_${new Date().toISOString().replace(/[:.]/g, "-")}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, [policy]);

  const copyPolicy = useCallback(async () => {
    await navigator.clipboard.writeText(JSON.stringify(policy, null, 2));
  }, [policy]);

  // тестер: поиск совпадений
  const testMatches = useMemo(() => {
    const text = testerText || "";
    const rows: { rule: Rule; hits: Array<{ start: number; end: number; match: string }> }[] = [];
    for (const r of policy.rules) {
      if (!r.enabled) continue;
      const re = safeRegex(r.pattern);
      if (!re) continue;
      const hits: Array<{ start: number; end: number; match: string }> = [];
      let m: RegExpExecArray | null;
      while ((m = re.exec(text)) !== null) {
        const start = m.index;
        const end = m.index + (m[0]?.length || 0);
        hits.push({ start, end, match: m[0] || "" });
        if (m.index === re.lastIndex) re.lastIndex++;
      }
      if (hits.length) rows.push({ rule: r, hits });
    }
    return rows;
  }, [testerText, policy]);

  const highlightedTester = useMemo(() => {
    const text = testerText;
    if (!text) return "";
    // плоский список всех попаданий
    const spans: Array<{ start: number; end: number; rule: Rule }> = [];
    for (const row of testMatches) for (const h of row.hits) spans.push({ start: h.start, end: h.end, rule: row.rule });
    spans.sort((a, b) => a.start - b.start);

    let out = "";
    let idx = 0;
    for (const s of spans) {
      if (s.start > idx) out += escapeHtml(text.slice(idx, s.start));
      const label = `${s.rule.category.toUpperCase()}:${s.rule.severity.toUpperCase()}`;
      out += `<mark class="rounded px-0.5">${escapeHtml(text.slice(s.start, s.end))}</mark><sup class="text-[10px] ml-1">${label}</sup>`;
      idx = s.end;
    }
    if (idx < text.length) out += escapeHtml(text.slice(idx));
    return out;
  }, [testerText, testMatches]);

  // -------------------------------- Render --------------------------------

  const enabledCount = policy.rules.filter(r => r.enabled).length;

  return (
    <div className="container mx-auto max-w-7xl p-6 space-y-6">
      <header className="flex items-start justify-between gap-4">
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5" />
            <h1 className="text-2xl font-semibold tracking-tight">Ethics Control Panel</h1>
            <Badge variant="secondary" className="ml-2">Policy {short(policyHash)}</Badge>
          </div>
          <p className="text-muted-foreground">
            Редактор правил, тестирование и управление версиями. Все данные сохраняются локально (localStorage).
          </p>
        </div>

        <Card className="min-w-[340px]">
          <CardHeader className="pb-3">
            <CardTitle className="text-base flex items-center gap-2">
              <ListChecks className="h-4 w-4" />
              Сводка политики
            </CardTitle>
            <CardDescription>Метаданные текущего состояния</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            <MetaRow label="Правил всего" value={`${policy.rules.length}`} />
            <MetaRow label="Включено" value={`${enabledCount}`} />
            <MetaRow label="Хэш" value={policyHash} mono />
          </CardContent>
          <CardFooter className="justify-between">
            <Button variant="secondary" className="gap-2" onClick={() => exportPolicy()}>
              <Download className="h-4 w-4" /> Экспорт
            </Button>
            <Button variant="outline" className="gap-2" onClick={copyPolicy}>
              <Copy className="h-4 w-4" /> Копировать
            </Button>
          </CardFooter>
        </Card>
      </header>

      <Tabs defaultValue="rules" className="w-full">
        <TabsList className="grid grid-cols-4">
          <TabsTrigger value="rules" className="flex items-center gap-2"><Settings2 className="h-4 w-4" /> Правила</TabsTrigger>
          <TabsTrigger value="tester" className="flex items-center gap-2"><ScanLine className="h-4 w-4" /> Тестер</TabsTrigger>
          <TabsTrigger value="versions" className="flex items-center gap-2"><History className="h-4 w-4" /> Версии</TabsTrigger>
          <TabsTrigger value="settings" className="flex items-center gap-2"><Layers3 className="h-4 w-4" /> Настройки</TabsTrigger>
        </TabsList>

        {/* RULES TAB */}
        <TabsContent value="rules" className="mt-4 space-y-6">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base flex items-center gap-2"><Plus className="h-4 w-4" />Новое правило</CardTitle>
              <CardDescription>Заполните обязательные поля и сохраните</CardDescription>
            </CardHeader>
            <CardContent className="grid md:grid-cols-2 gap-4">
              <div className="grid gap-2">
                <Label htmlFor="title">Название</Label>
                <Input 
                  id="title" 
                  placeholder="Короткое название" 
                  value={newRule.title}
                  onChange={(e) => setNewRule(prev => ({ ...prev, title: e.target.value }))}
                />
                {newErrors.title && <Err text={newErrors.title} />}
              </div>
              <div className="grid gap-2">
                <Label htmlFor="id">ID</Label>
                <Input 
                  id="id" 
                  placeholder="rule-xxxx" 
                  value={newRule.id}
                  onChange={(e) => setNewRule(prev => ({ ...prev, id: e.target.value }))}
                />
                {newErrors.id && <Err text={newErrors.id} />}
              </div>
              <div className="grid gap-2 md:col-span-2">
                <Label htmlFor="description">Описание</Label>
                <Textarea 
                  id="description" 
                  rows={3} 
                  value={newRule.description}
                  onChange={(e) => setNewRule(prev => ({ ...prev, description: e.target.value }))}
                />
                {newErrors.description && <Err text={newErrors.description} />}
              </div>
              <div className="grid gap-2">
                <Label>Категория</Label>
                <Select 
                  value={newRule.category}
                  onValueChange={(v: RiskCategory) => setNewRule(prev => ({ ...prev, category: v }))}
                >
                  <SelectTrigger><SelectValue placeholder="Выберите" /></SelectTrigger>
                  <SelectContent>
                    {CATEGORIES.map(c => <SelectItem key={c.value} value={c.value}>{c.label}</SelectItem>)}
                  </SelectContent>
                </Select>
                {newErrors.category && <Err text={newErrors.category} />}
              </div>
              <div className="grid gap-2">
                <Label>Серьезность</Label>
                <Select 
                  value={newRule.severity}
                  onValueChange={(v: RuleSeverity) => setNewRule(prev => ({ ...prev, severity: v }))}
                >
                  <SelectTrigger><SelectValue placeholder="Выберите" /></SelectTrigger>
                  <SelectContent>
                    {SEVERITIES.map(s => <SelectItem key={s.value} value={s.value}>{s.label}</SelectItem>)}
                  </SelectContent>
                </Select>
                {newErrors.severity && <Err text={newErrors.severity} />}
              </div>
              <div className="grid gap-2 md:col-span-2">
                <Label htmlFor="pattern">Regex-паттерн (необязательно)</Label>
                <Input 
                  id="pattern" 
                  placeholder="\\b(example)\\b" 
                  value={newRule.pattern || ""}
                  onChange={(e) => setNewRule(prev => ({ ...prev, pattern: e.target.value }))}
                />
                {newErrors.pattern && <Err text={newErrors.pattern} />}
              </div>
              <div className="grid gap-2 md:col-span-2">
                <Label htmlFor="hint">Подсказка (необязательно)</Label>
                <Input 
                  id="hint" 
                  placeholder="Как смягчить/переформулировать" 
                  value={newRule.hint || ""}
                  onChange={(e) => setNewRule(prev => ({ ...prev, hint: e.target.value }))}
                />
                {newErrors.hint && <Err text={newErrors.hint} />}
              </div>
              <div className="flex items-center justify-between rounded-lg border p-3 md:col-span-2">
                <div className="space-y-1">
                  <p className="text-sm font-medium">Включить правило</p>
                  <p className="text-xs text-muted-foreground">Сразу активировать после сохранения</p>
                </div>
                <Switch 
                  checked={newRule.enabled}
                  onCheckedChange={(checked) => setNewRule(prev => ({ ...prev, enabled: checked }))}
                />
              </div>
            </CardContent>
            <CardFooter className="justify-between">
              <Button className="gap-2" onClick={submitNew(addRule)} disabled={newSaving}>
                <Save className="h-4 w-4" /> Сохранить правило
              </Button>
              <Button variant="secondary" className="gap-2" onClick={() => resetNew()}>
                <RefreshCcw className="h-4 w-4" /> Очистить форму
              </Button>
            </CardFooter>
          </Card>

          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base flex items-center gap-2"><Filter className="h-4 w-4" />Фильтры</CardTitle>
              <CardDescription>Поиск и массовые операции</CardDescription>
            </CardHeader>
            <CardContent className="grid md:grid-cols-4 gap-3">
              <div className="grid gap-2 md:col-span-2">
                <Label>Поиск</Label>
                <div className="flex items-center gap-2">
                  <Search className="h-4 w-4 text-muted-foreground" />
                  <Input placeholder="ID, название, описание, regex" value={q} onChange={(e) => setQ(e.target.value)} />
                </div>
              </div>
              <div className="grid gap-2">
                <Label>Категория</Label>
                <Select value={cat} onValueChange={(v: RiskCategory | "all") => setCat(v)}>
                  <SelectTrigger><SelectValue placeholder="Все" /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">Все</SelectItem>
                    {CATEGORIES.map(c => <SelectItem key={c.value} value={c.value}>{c.label}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-2">
                <Label>Серьезность</Label>
                <Select value={sev} onValueChange={(v: RuleSeverity | "all") => setSev(v)}>
                  <SelectTrigger><SelectValue placeholder="Все" /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">Все</SelectItem>
                    {SEVERITIES.map(s => <SelectItem key={s.value} value={s.value}>{s.label}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
              <div className="flex items-center justify-between rounded-lg border p-3 md:col-span-4">
                <div className="space-y-1">
                  <p className="text-sm font-medium">Показывать только включенные</p>
                  <p className="text-xs text-muted-foreground">Фильтрация списка правил по статусу</p>
                </div>
                <Switch checked={onlyEnabled} onCheckedChange={setOnlyEnabled} />
              </div>

              <div className="flex flex-wrap gap-2 md:col-span-4">
                <Button variant="secondary" className="gap-2" onClick={() => bulkToggleAll(true)}>
                  <CheckSquare className="h-4 w-4" /> Включить все
                </Button>
                <Button variant="secondary" className="gap-2" onClick={() => bulkToggleAll(false)}>
                  <Square className="h-4 w-4" /> Выключить все
                </Button>
                {CATEGORIES.map(c => (
                  <Button key={c.value} variant="outline" className="gap-2"
                    onClick={() => bulkToggleCategory(c.value, true)}>
                    <CheckSquare className="h-4 w-4" /> {c.label}
                  </Button>
                ))}
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base flex items-center gap-2"><Settings2 className="h-4 w-4" />Список правил</CardTitle>
              <CardDescription>Редактирование в строке, дублирование и удаление</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="rounded-md border">
                <div className="grid grid-cols-12 px-4 py-2 text-xs font-medium text-muted-foreground">
                  <div className="col-span-2">ID</div>
                  <div className="col-span-2">Название</div>
                  <div className="col-span-2">Категория</div>
                  <div className="col-span-1">Серьезн.</div>
                  <div className="col-span-3">Regex</div>
                  <div className="col-span-2 text-right">Действия</div>
                </div>
                <Separator />
                <ScrollArea className="max-h-[420px]">
                  {filtered.map(r => (
                    <div key={r.id} className="grid grid-cols-12 px-4 py-2 text-sm items-center">
                      {editingId === r.id && editRule ? (
                        <>
                          <div className="col-span-2">
                            <Input 
                              value={editRule.id} 
                              onChange={(e) => setEditRule(prev => prev ? { ...prev, id: e.target.value } : null)}
                            />
                          </div>
                          <div className="col-span-2">
                            <Input 
                              value={editRule.title} 
                              onChange={(e) => setEditRule(prev => prev ? { ...prev, title: e.target.value } : null)}
                            />
                          </div>
                          <div className="col-span-2">
                            <Select 
                              value={editRule.category} 
                              onValueChange={(v: RiskCategory) => setEditRule(prev => prev ? { ...prev, category: v } : null)}
                            >
                              <SelectTrigger><SelectValue /></SelectTrigger>
                              <SelectContent>
                                {CATEGORIES.map(c => <SelectItem key={c.value} value={c.value}>{c.label}</SelectItem>)}
                              </SelectContent>
                            </Select>
                          </div>
                          <div className="col-span-1">
                            <Select 
                              value={editRule.severity} 
                              onValueChange={(v: RuleSeverity) => setEditRule(prev => prev ? { ...prev, severity: v } : null)}
                            >
                              <SelectTrigger><SelectValue /></SelectTrigger>
                              <SelectContent>
                                {SEVERITIES.map(s => <SelectItem key={s.value} value={s.value}>{s.label}</SelectItem>)}
                              </SelectContent>
                            </Select>
                          </div>
                          <div className="col-span-3">
                            <Input 
                              value={editRule.pattern || ""} 
                              placeholder="regex"
                              onChange={(e) => setEditRule(prev => prev ? { ...prev, pattern: e.target.value } : null)}
                            />
                          </div>
                          <div className="col-span-2 flex justify-end gap-2">
                            <Button size="sm" className="gap-1" onClick={submitEdit(saveEdit)} disabled={editSaving}><Save className="h-4 w-4" />Сохранить</Button>
                            <Button size="sm" variant="secondary" onClick={() => setEditingId(null)}><XCircle className="h-4 w-4" />Отмена</Button>
                          </div>
                          <div className="col-span-12 mt-2">
                            <Label>Описание</Label>
                            <Input 
                              value={editRule.description} 
                              onChange={(e) => setEditRule(prev => prev ? { ...prev, description: e.target.value } : null)}
                            />
                            {editErrors.description && <Err text={editErrors.description} />}
                          </div>
                          <div className="col-span-12 mt-2">
                            <div className="flex items-center justify-between rounded-lg border p-3">
                              <div className="space-y-1">
                                <p className="text-sm font-medium">Включено</p>
                                <p className="text-xs text-muted-foreground">Переключить статус правила</p>
                              </div>
                              <Switch 
                                checked={editRule.enabled} 
                                onCheckedChange={(checked) => setEditRule(prev => prev ? { ...prev, enabled: checked } : null)}
                              />
                            </div>
                          </div>
                        </>
                      ) : (
                        <>
                          <div className="col-span-2 font-mono">{r.id}</div>
                          <div className="col-span-2">{r.title}</div>
                          <div className="col-span-2"><Badge variant="secondary">{labelCategory(r.category)}</Badge></div>
                          <div className="col-span-1"><SeverityBadge severity={r.severity} /></div>
                          <div className="col-span-3"><code className="text-xs bg-muted px-1 py-0.5 rounded">{short(r.pattern || "", 18, 8)}</code></div>
                          <div className="col-span-2 flex justify-end gap-2">
                            <TooltipProvider>
                              <Tooltip>
                                <TooltipTrigger asChild>
                                  <Button size="sm" variant="outline" onClick={() => startEdit(r)} className="gap-1"><Edit3 className="h-4 w-4" />Ред.</Button>
                                </TooltipTrigger>
                                <TooltipContent>Редактировать</TooltipContent>
                              </Tooltip>
                            </TooltipProvider>
                            <Button size="sm" variant={r.enabled ? "secondary" : "outline"} onClick={() => toggleRule(r.id, !r.enabled)}>
                              {r.enabled ? "Выключить" : "Включить"}
                            </Button>
                            <Button size="sm" variant="outline" onClick={() => duplicateRule(r.id)}>Дублир.</Button>
                            <Button size="sm" variant="destructive" onClick={() => removeRule(r.id)} className="gap-1"><Trash2 className="h-4 w-4" />Удалить</Button>
                          </div>
                        </>
                      )}
                      <Separator className="col-span-12 my-2" />
                    </div>
                  ))}
                </ScrollArea>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* TESTER TAB */}
        <TabsContent value="tester" className="mt-4 space-y-6">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base flex items-center gap-2"><ScanLine className="h-4 w-4" />Текст для теста</CardTitle>
              <CardDescription>Вставьте пример ответа/контента</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <Textarea rows={10} value={testerText} onChange={(e) => setTesterText(e.target.value)} placeholder="Вставьте текст..." />
              <div className="flex items-center justify-between">
                <div className="text-xs text-muted-foreground flex items-center gap-2">
                  <Info className="h-3 w-3" /> Используются только включенные правила
                </div>
                <Badge variant="secondary" className="flex items-center gap-1">
                  <ListChecks className="h-3 w-3" /> Совпадений: {testMatches.reduce((a, b) => a + b.hits.length, 0)}
                </Badge>
              </div>
            </CardContent>
          </Card>

          <div className="grid md:grid-cols-2 gap-6">
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2"><Spline className="h-4 w-4" />Подсветка совпадений</CardTitle>
                <CardDescription>Сегменты текста с метками категорий</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="rounded-md border p-3 min-h-[240px] prose prose-sm max-w-none">
                  {/* eslint-disable-next-line react/no-danger */}
                  <div dangerouslySetInnerHTML={{ __html: highlightedTester }} />
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base">Сводная таблица совпадений</CardTitle>
                <CardDescription>По правилам и числу попаданий</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {testMatches.length === 0 ? (
                  <Alert>
                    <AlertTitle className="flex items-center gap-2"><CheckCircle2 className="h-4 w-4" />Ничего не найдено</AlertTitle>
                    <AlertDescription>Совпадений нет</AlertDescription>
                  </Alert>
                ) : (
                  <div className="rounded-md border">
                    <div className="grid grid-cols-12 px-4 py-2 text-xs font-medium text-muted-foreground">
                      <div className="col-span-5">Правило</div>
                      <div className="col-span-3">Категория</div>
                      <div className="col-span-2">Серьезн.</div>
                      <div className="col-span-2 text-right">Хиты</div>
                    </div>
                    <Separator />
                    <ScrollArea className="max-h-[300px]">
                      {testMatches.map(row => (
                        <div key={row.rule.id} className="grid grid-cols-12 px-4 py-2 text-sm">
                          <div className="col-span-5">{row.rule.title}</div>
                          <div className="col-span-3"><Badge variant="secondary">{labelCategory(row.rule.category)}</Badge></div>
                          <div className="col-span-2"><SeverityBadge severity={row.rule.severity} /></div>
                          <div className="col-span-2 text-right font-mono">{row.hits.length}</div>
                          <Separator className="col-span-12 my-2" />
                        </div>
                      ))}
                    </ScrollArea>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* VERSIONS TAB */}
        <TabsContent value="versions" className="mt-4">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base flex items-center gap-2"><GitBranch className="h-4 w-4" />Журнал версий</CardTitle>
              <CardDescription>Снапшоты политики и откат</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="rounded-md border">
                <div className="grid grid-cols-12 px-4 py-2 text-xs font-medium text-muted-foreground">
                  <div className="col-span-3">ID</div>
                  <div className="col-span-3">Создано</div>
                  <div className="col-span-3">Хэш</div>
                  <div className="col-span-1 text-right">Правил</div>
                  <div className="col-span-1 text-right">Вкл.</div>
                  <div className="col-span-1 text-right">Действия</div>
                </div>
                <Separator />
                <ScrollArea className="max-h-[420px]">
                  {versions.map(v => (
                    <div key={v.id} className="grid grid-cols-12 px-4 py-2 text-sm items-center">
                      <div className="col-span-3 font-mono">{v.id}</div>
                      <div className="col-span-3">{new Date(v.createdAt).toLocaleString()}</div>
                      <div className="col-span-3 font-mono"><HashIcon className="inline-block h-3 w-3 mr-1" />{short(v.hash)}</div>
                      <div className="col-span-1 text-right">{v.rulesCount}</div>
                      <div className="col-span-1 text-right">{v.enabledCount}</div>
                      <div className="col-span-1 text-right">
                        <div className="flex justify-end gap-2">
                          <Button size="sm" variant="secondary" onClick={() => exportPolicy(v.policy)}><Download className="h-4 w-4" /></Button>
                          <Button size="sm" onClick={() => revertTo(v.id)}><RefreshCcw className="h-4 w-4" /></Button>
                        </div>
                      </div>
                      <Separator className="col-span-12 my-2" />
                    </div>
                  ))}
                </ScrollArea>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* SETTINGS TAB */}
        <TabsContent value="settings" className="mt-4 space-y-6">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base flex items-center gap-2"><UploadCloud className="h-4 w-4" />Импорт политики</CardTitle>
              <CardDescription>JSON по схеме {`{ rules: Rule[] }`}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <Input type="file" accept=".json,application/json" onChange={(e) => {
                const f = e.target.files?.[0]; if (f) importFromFile(f);
              }} />
              <Textarea rows={14} value={importText} onChange={(e) => setImportText(e.target.value)} />
            </CardContent>
            <CardFooter className="justify-between">
              <Button className="gap-2" onClick={applyImport}><Save className="h-4 w-4" />Применить</Button>
              <Button variant="secondary" className="gap-2" onClick={resetDefaults}><AlertTriangle className="h-4 w-4" />Сброс по умолчанию</Button>
            </CardFooter>
          </Card>

          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base">Экспорт / Копирование</CardTitle>
              <CardDescription>Сохранить в файл или буфер обмена</CardDescription>
            </CardHeader>
            <CardContent className="flex items-center gap-3">
              <Button className="gap-2" onClick={() => exportPolicy()}><Download className="h-4 w-4" />Экспорт JSON</Button>
              <Button variant="secondary" className="gap-2" onClick={copyPolicy}><Copy className="h-4 w-4" />Копировать JSON</Button>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

// -------------------------------- Subcomponents --------------------------------

function MetaRow({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-center justify-between gap-4">
      <span className="text-xs text-muted-foreground">{label}</span>
      <span className={`text-xs ${mono ? "font-mono" : ""} truncate max-w-[70%]`} title={value}>{value}</span>
    </div>
  );
}

function Err({ text }: { text: string }) {
  return <p className="text-xs text-destructive">{text}</p>;
}

function labelCategory(c: RiskCategory) {
  const f = CATEGORIES.find(x => x.value === c);
  return f ? f.label : c;
}

function SeverityBadge({ severity }: { severity: RuleSeverity }) {
  const map: Record<RuleSeverity, { label: string; variant: "default" | "secondary" | "destructive" }> = {
    low: { label: "Низкая", variant: "secondary" },
    medium: { label: "Средняя", variant: "default" },
    high: { label: "Высокая", variant: "default" },
    critical: { label: "Критическая", variant: "destructive" },
  };
  const v = map[severity] || map.medium;
  return <Badge variant={v.variant}>{v.label}</Badge>;
}



function escapeHtml(s: string) {
  return s
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export default EthicsControlPanel;
