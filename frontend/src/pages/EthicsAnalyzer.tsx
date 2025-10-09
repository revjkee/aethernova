// frontend/src/pages/EthicsAnalyzer.tsx

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
import { Progress } from "@/components/ui/progress";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";

import {
  ShieldCheck, FileText, UploadCloud, Download, Scale, Filter, Wand2,
  AlertTriangle, CircleHelp, Database, ListChecks, Loader2, LockKeyhole,
  BarChart3, CheckCircle2, XCircle, RefreshCcw, Settings2, History, Info, Sparkles
} from "lucide-react";

import {
  BarChart, Bar, ResponsiveContainer, CartesianGrid, XAxis, YAxis, Legend, Tooltip as RTooltip, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar,
} from "recharts";

// --------------------------- Types & Schemas ---------------------------

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
  pattern?: string; // optional regex string
  hint?: string;
  enabled: boolean;
};

type Finding = {
  ruleId: string;
  title: string;
  category: RiskCategory;
  severity: RuleSeverity;
  excerpt: string;
  positions: Array<{ start: number; end: number }>;
  explanation: string;
};

type ScoreBreakdown = Record<RiskCategory, number>; // 0..100

type Report = {
  createdAt: string;
  engineVersion: string;
  inputSample: {
    prompt?: string;
    modelOutput?: string;
  };
  findings: Finding[];
  score: {
    overall: number; // 0..100 the lower is better risk; we invert later for chart if needed
    breakdown: ScoreBreakdown;
  };
  policyHash: string;
  policyRulesCount: number;
  meta?: Record<string, string | number | boolean>;
};

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

const policySchema = z.object({
  rules: z.array(z.object({
    id: z.string(),
    title: z.string(),
    description: z.string(),
    category: z.custom<RiskCategory>(),
    severity: z.custom<RuleSeverity>(),
    pattern: z.string().optional(),
    hint: z.string().optional(),
    enabled: z.boolean(),
  })),
});

const inputSchema = z.object({
  prompt: z.string().optional(),
  modelOutput: z.string().optional(),
  strictMode: z.boolean().default(true),
});

type AnalyzerInput = z.infer<typeof inputSchema>;

// --------------------------- Utility Helpers ---------------------------

function makeHash(s: string): string {
  // Simple non-crypto hash for display purposes
  let h = 0, i = 0, len = s.length;
  while (i < len) {
    h = (h << 5) - h + s.charCodeAt(i++) | 0;
  }
  return `h${(h >>> 0).toString(16)}`;
}

function short(s?: string, head = 8, tail = 6) {
  if (!s) return "—";
  if (s.length <= head + tail + 3) return s;
  return `${s.slice(0, head)}...${s.slice(-tail)}`;
}

function nowISO() {
  return new Date().toISOString();
}

function clamp(n: number, min = 0, max = 100) {
  return Math.max(min, Math.min(max, n));
}

function severityWeight(s: RuleSeverity): number {
  switch (s) {
    case "low": return 1;
    case "medium": return 3;
    case "high": return 6;
    case "critical": return 10;
    default: return 1;
  }
}

function categoryLabel(c: RiskCategory): string {
  const map: Record<RiskCategory, string> = {
    privacy: "Приватность",
    bias: "Предвзятость",
    toxicity: "Токсичность",
    selfharm: "Самоповреждение",
    medical: "Медицина",
    legal: "Юридическое",
    copyright: "Авторское право",
    violence: "Насилие/Оружие",
    politics: "Политика",
    safety: "Безопасность",
  };
  return map[c] || c;
}

// --------------------------- Rule Engine ---------------------------

function evaluateTextAgainstRules(text: string, rules: Rule[]): Finding[] {
  const findings: Finding[] = [];
  for (const r of rules) {
    if (!r.enabled) continue;
    if (!r.pattern) continue;
    try {
      const re = new RegExp(r.pattern, "gi");
      let m: RegExpExecArray | null;
      while ((m = re.exec(text)) !== null) {
        const start = m.index;
        const end = m.index + (m[0]?.length || 0);
        findings.push({
          ruleId: r.id,
          title: r.title,
          category: r.category,
          severity: r.severity,
          excerpt: text.slice(Math.max(0, start - 40), Math.min(text.length, end + 40)),
          positions: [{ start, end }],
          explanation: r.description + (r.hint ? ` Рекомендация: ${r.hint}` : ""),
        });
        // prevent infinite loop on zero-length matches
        if (m.index === re.lastIndex) re.lastIndex++;
      }
    } catch {
      // invalid regex — skip rule safely
      continue;
    }
  }
  return findings;
}

function scoreFromFindings(findings: Finding[]): { overall: number; breakdown: ScoreBreakdown } {
  const categories: RiskCategory[] = ["privacy","bias","toxicity","selfharm","medical","legal","copyright","violence","politics","safety"];
  const acc: ScoreBreakdown = Object.fromEntries(categories.map(c => [c, 0])) as ScoreBreakdown;

  for (const f of findings) {
    acc[f.category] += severityWeight(f.severity) * 10; // base contribution
  }

  // Normalize to 0..100
  const breakdown = categories.reduce((o, c) => {
    o[c] = clamp(acc[c], 0, 100);
    return o;
  }, {} as ScoreBreakdown);

  // Overall as weighted average
  const total = findings.reduce((s, f) => s + severityWeight(f.severity), 0);
  const maxPossible = 10 * 10; // arbitrary cap for normalization
  const overall = clamp(Math.round((total / maxPossible) * 100));

  return { overall, breakdown };
}

// --------------------------- Component ---------------------------

const EthicsAnalyzer: React.FC = () => {
  // Policy state
  const [policy, setPolicy] = useState<Rule[]>(() => DEFAULT_RULES);
  const policyHash = useMemo(() => makeHash(JSON.stringify(policy.map(({ id, enabled }) => ({ id, enabled })))), [policy]);

  // Inputs
  const [formData, setFormData] = useState<AnalyzerInput>({
    prompt: "",
    modelOutput: "",
    strictMode: true,
  });
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Results
  const [findings, setFindings] = useState<Finding[]>([]);
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Loading/UX
  const [scanning, setScanning] = useState(false);
  const [policyJson, setPolicyJson] = useState<string>(() => JSON.stringify({ rules: DEFAULT_RULES }, null, 2));
  const [autoMitigation, setAutoMitigation] = useState(true);

  // Derived
  const sampleText = useMemo(() => {
    const p = formData.prompt?.trim() || "";
    const o = formData.modelOutput?.trim() || "";
    return [p, o].filter(Boolean).join("\n---\n");
  }, [formData.prompt, formData.modelOutput]);

  const chartBarData = useMemo(() => {
    const br = report?.score.breakdown;
    if (!br) return [];
    return Object.entries(br).map(([k, v]) => ({ category: categoryLabel(k as RiskCategory), score: v }));
  }, [report]);

  const chartRadarData = chartBarData;

  // Handlers
  const runScan = useCallback(() => {
    setScanning(true);
    setError(null);
    setIsSubmitting(true);
    try {
      const text = [formData.prompt?.trim(), formData.modelOutput?.trim()].filter(Boolean).join("\n---\n");
      const f = evaluateTextAgainstRules(text, policy);
      const s = scoreFromFindings(f);

      const rep: Report = {
        createdAt: nowISO(),
        engineVersion: "ethics-analyzer/1.0.0",
        inputSample: { prompt: formData.prompt || "", modelOutput: formData.modelOutput || "" },
        findings: f,
        score: { overall: s.overall, breakdown: s.breakdown },
        policyHash,
        policyRulesCount: policy.length,
        meta: { strictMode: formData.strictMode },
      };
      setFindings(f);
      setReport(rep);
    } catch (e: any) {
      setError(e?.message || "Не удалось выполнить анализ");
    } finally {
      setScanning(false);
      setIsSubmitting(false);
    }
  }, [formData, policy, policyHash]);

  const importPolicy = useCallback((file: File) => {
    setError(null);
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const txt = String(reader.result || "");
        setPolicyJson(txt);
        const parsed = policySchema.parse(JSON.parse(txt));
        setPolicy(parsed.rules);
      } catch (e: any) {
        setError(e?.message || "Ошибка парсинга политики");
      }
    };
    reader.readAsText(file);
  }, []);

  const exportReport = useCallback(() => {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `ethics_report_${new Date().toISOString().replace(/[:.]/g, "-")}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, [report]);

  const applyPolicyJson = useCallback(() => {
    setError(null);
    try {
      const parsed = policySchema.parse(JSON.parse(policyJson));
      setPolicy(parsed.rules);
    } catch (e: any) {
      setError(e?.message || "Ошибка применения политики");
    }
  }, [policyJson]);

  const resetPolicy = useCallback(() => {
    setPolicy(DEFAULT_RULES);
    setPolicyJson(JSON.stringify({ rules: DEFAULT_RULES }, null, 2));
  }, []);

  const mitigatedOutput = useMemo(() => {
    if (!autoMitigation || !report) return formData.modelOutput || "";
    let text = formData.modelOutput || "";
    for (const f of report.findings) {
      // simple mitigation: mask excerpt location
      for (const pos of f.positions) {
        const before = text.slice(0, pos.start);
        const target = text.slice(pos.start, pos.end);
        const after = text.slice(pos.end);
        if (!target) continue;
        text = `${before}[REDACTED:${f.category.toUpperCase()}]${after}`;
      }
    }
    return text;
  }, [autoMitigation, report, formData.modelOutput]);

  // --------------------------- Render ---------------------------

  return (
    <div className="container mx-auto max-w-7xl p-6 space-y-6">
      <header className="flex items-start justify-between gap-4">
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5" />
            <h1 className="text-2xl font-semibold tracking-tight">Ethics Analyzer</h1>
            <Badge variant="secondary" className="ml-2">Policy {short(policyHash)}</Badge>
          </div>
          <p className="text-muted-foreground">
            Локальный анализ рисков контента и объяснимость по набору включаемых правил. Импорт/экспорт политики и отчетов.
          </p>
        </div>
        <Card className="min-w-[320px]">
          <CardHeader className="pb-3">
            <CardTitle className="text-base flex items-center gap-2">
              <ListChecks className="h-4 w-4" />
              Сводка
            </CardTitle>
            <CardDescription>Конфигурация сеанса</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            <MetaRow label="Правил включено" value={`${policy.filter(r => r.enabled).length}/${policy.length}`} />
            <MetaRow label="Policy hash" value={policyHash} mono />
            <MetaRow label="Версия движка" value="ethics-analyzer/1.0.0" />
            <div className="flex items-center justify-between">
              <span className="text-xs text-muted-foreground">Автосмягчение вывода</span>
              <Switch checked={autoMitigation} onCheckedChange={setAutoMitigation} />
            </div>
          </CardContent>
        </Card>
      </header>

      <Tabs defaultValue="input" className="w-full">
        <TabsList className="grid grid-cols-4">
          <TabsTrigger value="input" className="flex items-center gap-2"><FileText className="h-4 w-4" /> Ввод</TabsTrigger>
          <TabsTrigger value="results" className="flex items-center gap-2"><Scale className="h-4 w-4" /> Результаты</TabsTrigger>
          <TabsTrigger value="dashboard" className="flex items-center gap-2"><BarChart3 className="h-4 w-4" /> Дашборды</TabsTrigger>
          <TabsTrigger value="policy" className="flex items-center gap-2"><Settings2 className="h-4 w-4" /> Политика</TabsTrigger>
        </TabsList>

        {/* INPUT TAB */}
        <TabsContent value="input" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Текст для анализа</CardTitle>
              <CardDescription>Заполните один или оба поля</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid md:grid-cols-2 gap-4">
                <div className="grid gap-2">
                  <Label htmlFor="prompt">Промпт/Контекст</Label>
                  <Textarea 
                    id="prompt" 
                    rows={10} 
                    placeholder="Введите исходный запрос пользователя или контекст"
                    value={formData.prompt || ""}
                    onChange={(e) => setFormData(prev => ({ ...prev, prompt: e.target.value }))}
                  />
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="modelOutput">Ответ модели</Label>
                  <Textarea 
                    id="modelOutput" 
                    rows={10} 
                    placeholder="Вставьте ответ модели для проверки"
                    value={formData.modelOutput || ""}
                    onChange={(e) => setFormData(prev => ({ ...prev, modelOutput: e.target.value }))}
                  />
                </div>
              </div>

              <div className="flex items-center justify-between rounded-lg border p-3">
                <div className="space-y-1">
                  <p className="text-sm font-medium">Строгий режим</p>
                  <p className="text-xs text-muted-foreground">Повышенные штрафы за критичные категории</p>
                </div>
                <Switch 
                  checked={formData.strictMode}
                  onCheckedChange={(checked) => setFormData(prev => ({ ...prev, strictMode: checked }))}
                />
              </div>
            </CardContent>
            <CardFooter className="flex items-center justify-between">
              <Button className="gap-2" onClick={runScan} disabled={scanning || isSubmitting}>
                {scanning ? <Loader2 className="h-4 w-4 animate-spin" /> : <Wand2 className="h-4 w-4" />}
                Запустить анализ
              </Button>
              <Button variant="secondary" className="gap-2" onClick={() => { 
                setFormData({ prompt: "", modelOutput: "", strictMode: true }); 
                setFindings([]); 
                setReport(null); 
              }}>
                <RefreshCcw className="h-4 w-4" />
                Сбросить
              </Button>
            </CardFooter>
          </Card>

          <div className="grid md:grid-cols-2 gap-6 mt-6">
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base">Митигированный вывод</CardTitle>
                <CardDescription>Автоматическое маскирование спорных фрагментов</CardDescription>
              </CardHeader>
              <CardContent>
                <Textarea value={mitigatedOutput} readOnly rows={12} />
              </CardContent>
              <CardFooter className="justify-end">
                <Button variant="secondary" className="gap-2" onClick={() => navigator.clipboard.writeText(mitigatedOutput)}>
                  <Sparkles className="h-4 w-4" />
                  Скопировать
                </Button>
              </CardFooter>
            </Card>

            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base">Статус анализа</CardTitle>
                <CardDescription>Прогресс и сообщения</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <Progress value={report ? 100 : scanning ? 60 : 0} />
                {error ? (
                  <Alert variant="destructive">
                    <AlertTitle className="flex items-center gap-2"><XCircle className="h-4 w-4" />Ошибка</AlertTitle>
                    <AlertDescription className="text-sm">{error}</AlertDescription>
                  </Alert>
                ) : report ? (
                  <Alert>
                    <AlertTitle className="flex items-center gap-2"><CheckCircle2 className="h-4 w-4" />Готово</AlertTitle>
                    <AlertDescription className="text-sm">Отчет сформирован {new Date(report.createdAt).toLocaleString()}</AlertDescription>
                  </Alert>
                ) : (
                  <Alert>
                    <AlertTitle className="flex items-center gap-2"><CircleHelp className="h-4 w-4" />Ожидание ввода</AlertTitle>
                    <AlertDescription className="text-sm">Заполните поля и запустите анализ</AlertDescription>
                  </Alert>
                )}
              </CardContent>
              <CardFooter className="justify-between">
                <Button variant="outline" className="gap-2" disabled={!report} onClick={exportReport}>
                  <Download className="h-4 w-4" />
                  Экспорт отчета (.json)
                </Button>
                <Badge variant="secondary" className="flex items-center gap-1">
                  <Database className="h-3 w-3" /> {findings.length} совпадений
                </Badge>
              </CardFooter>
            </Card>
          </div>
        </TabsContent>

        {/* RESULTS TAB */}
        <TabsContent value="results" className="mt-4">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base">Найденные несоответствия</CardTitle>
              <CardDescription>По категориям и серьезности</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {!report ? (
                <Alert>
                  <AlertTitle>Нет результатов</AlertTitle>
                  <AlertDescription>Сначала выполните анализ</AlertDescription>
                </Alert>
              ) : findings.length === 0 ? (
                <Alert>
                  <AlertTitle className="flex items-center gap-2"><ShieldCheck className="h-4 w-4" />Нарушений не обнаружено</AlertTitle>
                  <AlertDescription>С учетом текущей политики совпадений нет</AlertDescription>
                </Alert>
              ) : (
                <>
                  <div className="rounded-md border">
                    <div className="grid grid-cols-12 px-4 py-2 text-xs font-medium text-muted-foreground">
                      <div className="col-span-3">Правило</div>
                      <div className="col-span-2">Категория</div>
                      <div className="col-span-2">Серьезность</div>
                      <div className="col-span-5">Фрагмент</div>
                    </div>
                    <Separator />
                    <ScrollArea className="max-h-[360px]">
                      {findings.map((f, i) => (
                        <div key={`${f.ruleId}-${i}`} className="grid grid-cols-12 px-4 py-2 text-sm">
                          <div className="col-span-3 font-medium">{f.title}</div>
                          <div className="col-span-2">{categoryLabel(f.category)}</div>
                          <div className="col-span-2">
                            <SeverityBadge severity={f.severity} />
                          </div>
                          <div className="col-span-5">
                            <TooltipProvider>
                              <Tooltip>
                                <TooltipTrigger className="text-xs text-muted-foreground line-clamp-2 text-left">{f.excerpt}</TooltipTrigger>
                                <TooltipContent className="max-w-md">
                                  <p className="text-xs">{f.excerpt}</p>
                                </TooltipContent>
                              </Tooltip>
                            </TooltipProvider>
                          </div>
                          <div className="col-span-12 mt-2 text-xs text-muted-foreground">
                            <Info className="inline-block mr-1 h-3 w-3" />
                            {f.explanation}
                          </div>
                          <Separator className="col-span-12 my-2" />
                        </div>
                      ))}
                    </ScrollArea>
                  </div>
                </>
              )}
            </CardContent>
            {report && (
              <CardFooter className="justify-between">
                <div className="flex items-center gap-2">
                  <Label className="text-xs">Итоговый риск</Label>
                  <Badge variant={report.score.overall > 70 ? "destructive" : report.score.overall > 40 ? "secondary" : "default"}>
                    {report.score.overall}/100
                  </Badge>
                </div>
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  <History className="h-3 w-3" />
                  Отчет: {short(JSON.stringify(report).length.toString())} bytes
                </div>
              </CardFooter>
            )}
          </Card>
        </TabsContent>

        {/* DASHBOARD TAB */}
        <TabsContent value="dashboard" className="mt-4">
          <div className="grid lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base">Риск по категориям</CardTitle>
                <CardDescription>Нормализовано к 0–100 (хуже — больше)</CardDescription>
              </CardHeader>
              <CardContent className="h-[320px]">
                {report ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={chartBarData}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="category" />
                      <YAxis />
                      <RTooltip />
                      <Legend />
                      <Bar dataKey="score" name="Риск" />
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <SkeletonChart />
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base">Радар-профиль</CardTitle>
                <CardDescription>Силуэт рисков по доменам</CardDescription>
              </CardHeader>
              <CardContent className="h-[320px]">
                {report ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <RadarChart data={chartRadarData}>
                      <PolarGrid />
                      <PolarAngleAxis dataKey="category" />
                      <PolarRadiusAxis />
                      <Radar name="Риск" dataKey="score" />
                      <Legend />
                    </RadarChart>
                  </ResponsiveContainer>
                ) : (
                  <SkeletonChart />
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* POLICY TAB */}
        <TabsContent value="policy" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Политика и правила</CardTitle>
              <CardDescription>Импорт/экспорт JSON, включение/исключение правил</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid md:grid-cols-2 gap-4">
                <div className="grid gap-2">
                  <Label>JSON политика</Label>
                  <Textarea rows={18} value={policyJson} onChange={(e) => setPolicyJson(e.target.value)} />
                  <div className="flex items-center gap-2">
                    <Button className="gap-2" onClick={applyPolicyJson}><Filter className="h-4 w-4" /> Применить</Button>
                    <Button variant="secondary" className="gap-2" onClick={resetPolicy}><RefreshCcw className="h-4 w-4" /> Сбросить</Button>
                  </div>
                </div>
                <div className="grid gap-2">
                  <Label>Импорт из файла</Label>
                  <Input type="file" accept=".json,application/json" onChange={(e) => {
                    const f = e.target.files?.[0]; if (f) importPolicy(f);
                  }} />
                  <div className="rounded-md border p-3 space-y-2">
                    <p className="text-xs text-muted-foreground">Список активных правил</p>
                    <ScrollArea className="max-h-[240px]">
                      <div className="space-y-2">
                        {policy.map((r) => (
                          <div key={r.id} className="rounded border p-2">
                            <div className="flex items-center justify-between">
                              <div className="text-sm font-medium">{r.title}</div>
                              <Badge variant={r.enabled ? "default" : "secondary"}>{r.enabled ? "вкл" : "выкл"}</Badge>
                            </div>
                            <div className="text-xs text-muted-foreground">{r.description}</div>
                            <div className="mt-1 flex items-center gap-2 text-xs">
                              <Badge variant="secondary">{categoryLabel(r.category)}</Badge>
                              <SeverityBadge severity={r.severity} />
                              {r.pattern && <code className="text-[10px] bg-muted px-1 py-0.5 rounded">{short(r.pattern, 16, 8)}</code>}
                            </div>
                          </div>
                        ))}
                      </div>
                    </ScrollArea>
                  </div>
                </div>
              </div>
            </CardContent>
            <CardFooter className="justify-between">
              <div className="text-xs text-muted-foreground flex items-center gap-2">
                <LockKeyhole className="h-3 w-3" />
                Хэш политики: {policyHash}
              </div>
              <div className="text-xs text-muted-foreground flex items-center gap-2">
                <AlertTriangle className="h-3 w-3" />
                Неправильные regex будут безопасно пропущены
              </div>
            </CardFooter>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

// --------------------------- Subcomponents ---------------------------

function MetaRow({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-center justify-between gap-4">
      <span className="text-xs text-muted-foreground">{label}</span>
      <span className={`text-xs ${mono ? "font-mono" : ""} truncate max-w-[70%]`} title={value}>{value}</span>
    </div>
  );
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

function SkeletonChart() {
  return (
    <div className="h-full w-full flex items-center justify-center text-xs text-muted-foreground">
      Нет данных — выполните анализ
    </div>
  );
}

export default EthicsAnalyzer;
