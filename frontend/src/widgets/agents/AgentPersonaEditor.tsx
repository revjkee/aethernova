// frontend/src/widgets/agents/AgentPersonaEditor.tsx
"use client";

import * as React from "react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Separator } from "@/components/ui/separator";
import { Select, SelectTrigger, SelectContent, SelectItem, SelectGroup, SelectGroupLabel, SelectDisplayValue } from "@/components/ui/select";
import { cn, createNamespaceStorage, uuid, formatNumber } from "@/lib/utils";

/** Встроенные иконки (без lucide-react) */
const IconPlus: React.FC<React.SVGProps<SVGSVGElement>> = (p) => (
  <svg viewBox="0 0 24 24" aria-hidden="true" {...p}><path d="M12 5v14M5 12h14" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/></svg>
);
const IconTrash: React.FC<React.SVGProps<SVGSVGElement>> = (p) => (
  <svg viewBox="0 0 24 24" aria-hidden="true" {...p}><path d="M4 7h16M9 7v12m6-12v12M10 4h4l1 3H9l1-3z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" fill="none"/></svg>
);
const IconDownload: React.FC<React.SVGProps<SVGSVGElement>> = (p) => (
  <svg viewBox="0 0 24 24" aria-hidden="true" {...p}><path d="M12 3v12m0 0-4-4m4 4 4-4M5 21h14" stroke="currentColor" strokeWidth="2" fill="none"/></svg>
);
const IconUpload: React.FC<React.SVGProps<SVGSVGElement>> = (p) => (
  <svg viewBox="0 0 24 24" aria-hidden="true" {...p}><path d="M12 21V9m0 0 4 4m-4-4-4 4M5 3h14" stroke="currentColor" strokeWidth="2" fill="none"/></svg>
);
const IconCopy: React.FC<React.SVGProps<SVGSVGElement>> = (p) => (
  <svg viewBox="0 0 24 24" aria-hidden="true" {...p}><path d="M8 8h10v12H8z" stroke="currentColor" strokeWidth="2" fill="none"/><path d="M6 16H4V4h12v2" stroke="currentColor" strokeWidth="2"/></svg>
);
const IconUndo: React.FC<React.SVGProps<SVGSVGElement>> = (p) => (
  <svg viewBox="0 0 24 24" aria-hidden="true" {...p}><path d="M9 10H4V5" stroke="currentColor" strokeWidth="2" fill="none"/><path d="M4 10a8 8 0 1 0 2-5" stroke="currentColor" strokeWidth="2" fill="none"/></svg>
);
const IconRedo: React.FC<React.SVGProps<SVGSVGElement>> = (p) => (
  <svg viewBox="0 0 24 24" aria-hidden="true" {...p}><path d="M15 10h5V5" stroke="currentColor" strokeWidth="2" fill="none"/><path d="M20 10a8 8 0 1 1-2-5" stroke="currentColor" strokeWidth="2" fill="none"/></svg>
);
const IconRefresh: React.FC<React.SVGProps<SVGSVGElement>> = (p) => (
  <svg viewBox="0 0 24 24" aria-hidden="true" {...p}><path d="M21 12a9 9 0 10-3.5 7" stroke="currentColor" strokeWidth="2" fill="none"/><path d="M21 3v6h-6" stroke="currentColor" strokeWidth="2" fill="none"/></svg>
);

/** Типы данных персоны агента */
export type AgentGoal = { id: string; text: string };
export type AgentSkill = { id: string; text: string };
export type AgentConstraint = { id: string; text: string };

export type ToolPermission = {
  name: string;
  allowed: boolean;
  note?: string;
};

export type Persona = {
  id: string;
  name: string;
  role: "research" | "analyst" | "assistant" | "developer" | "operations" | "custom";
  description?: string;
  tone?: "neutral" | "formal" | "friendly" | "critical" | "inquisitive";
  style?: "concise" | "balanced" | "detailed";
  goals: AgentGoal[];
  skills: AgentSkill[];
  constraints: AgentConstraint[];
  tools: ToolPermission[];
  safety: {
    allowBrowsing: boolean;
    allowCodeExec: boolean;
    maxTokens: number;
    temperature: number; // 0..2
  };
  examples?: Array<{ title: string; input: string; output: string }>;
  metadata?: Record<string, string | number | boolean>;
};

/** Значения по умолчанию */
const DEFAULT_PERSONA: Persona = {
  id: uuid(),
  name: "Unnamed agent",
  role: "assistant",
  description: "",
  tone: "neutral",
  style: "balanced",
  goals: [{ id: uuid(), text: "Provide accurate, verifiable answers." }],
  skills: [{ id: uuid(), text: "Synthesize information from multiple sources." }],
  constraints: [{ id: uuid(), text: "Adhere to project safety and privacy rules." }],
  tools: [
    { name: "web", allowed: true, note: "Only for verifiable sources." },
    { name: "code", allowed: false, note: "Disabled by default." },
  ],
  safety: {
    allowBrowsing: true,
    allowCodeExec: false,
    maxTokens: 2048,
    temperature: 0.2,
  },
  examples: [],
  metadata: {},
};

/** Простая валидация (без сторонних библиотек) */
function validatePersona(p: Persona): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  if (!p.name?.trim()) errors.push("Name is required.");
  if (!p.role) errors.push("Role is required.");
  if (!Number.isFinite(p.safety.maxTokens) || p.safety.maxTokens <= 0) errors.push("maxTokens must be > 0.");
  if (!Number.isFinite(p.safety.temperature) || p.safety.temperature < 0 || p.safety.temperature > 2)
    errors.push("temperature must be in [0, 2].");
  const badGoal = p.goals.find((g) => !g.text?.trim());
  if (badGoal) errors.push("All goals must be non-empty.");
  const badSkill = p.skills.find((g) => !g.text?.trim());
  if (badSkill) errors.push("All skills must be non-empty.");
  const badConstr = p.constraints.find((g) => !g.text?.trim());
  if (badConstr) errors.push("All constraints must be non-empty.");
  return { valid: errors.length === 0, errors };
}

/** Хранилище и автосейв */
const storage = createNamespaceStorage("agent-persona-editor");
const STORAGE_KEY = "persona_draft";
const HISTORY_LIMIT = 50;

/** Утилиты */
function downloadBlob(content: string, fileName: string, mime = "application/json;charset=utf-8") {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = fileName;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

/** Элемент списка с инпутом и кнопками */
const EditableRow: React.FC<{
  value: string;
  onChange: (v: string) => void;
  onDelete?: () => void;
  placeholder?: string;
}> = ({ value, onChange, onDelete, placeholder }) => (
  <div className="flex items-center gap-2">
    <Input value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} />
    {onDelete && (
      <Button variant="outline" size="icon" onClick={onDelete} aria-label="Delete">
        <IconTrash className="h-4 w-4" />
      </Button>
    )}
  </div>
);

/** Главный компонент редактора персоны */
export type AgentPersonaEditorProps = {
  initial?: Persona;
  title?: string;
  description?: string;
  onChange?: (value: Persona) => void;
  onValidate?: (state: { valid: boolean; errors: string[] }) => void;
  readOnly?: boolean;
  className?: string;
};

export const AgentPersonaEditor: React.FC<AgentPersonaEditorProps> = ({
  initial,
  title = "Agent persona",
  description,
  onChange,
  onValidate,
  readOnly = false,
  className,
}) => {
  const [persona, setPersona] = useState<Persona>(() => {
    const saved = storage.get<Persona>(STORAGE_KEY);
    return saved ?? initial ?? DEFAULT_PERSONA;
  });

  /** История изменений (undo/redo) */
  const undoStack = useRef<Persona[]>([]);
  const redoStack = useRef<Persona[]>([]);
  const pushHistory = (p: Persona) => {
    undoStack.current.push(p);
    if (undoStack.current.length > HISTORY_LIMIT) undoStack.current.shift();
    redoStack.current = [];
  };
  const doUndo = () => {
    const prev = undoStack.current.pop();
    if (prev) {
      redoStack.current.push(persona);
      setPersona(prev);
    }
  };
  const doRedo = () => {
    const next = redoStack.current.pop();
    if (next) {
      undoStack.current.push(persona);
      setPersona(next);
    }
  };

  /** Применение изменения со снимком истории */
  const apply = useCallback((patch: Partial<Persona> | ((p: Persona) => Persona)) => {
    setPersona((cur) => {
      pushHistory(cur);
      const next = typeof patch === "function" ? (patch as any)(cur) : { ...cur, ...patch };
      return { ...next };
    });
  }, []);

  /** Автосохранение и валидация */
  useEffect(() => {
    storage.set(STORAGE_KEY, persona);
    onChange?.(persona);
    const v = validatePersona(persona);
    onValidate?.(v);
  }, [persona, onChange, onValidate]);

  /** Сброс к дефолту */
  const resetToDefault = () => {
    pushHistory(persona);
    setPersona({ ...DEFAULT_PERSONA, id: uuid() });
  };

  /** Импорт/экспорт */
  const doExport = () => downloadBlob(JSON.stringify(persona, null, 2), `persona_${persona.name || "agent"}.json`);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const doImport = () => fileInputRef.current?.click();
  const onFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    try {
      const obj = JSON.parse(text) as Persona;
      const validated = { ...DEFAULT_PERSONA, ...obj, id: obj.id || uuid() } as Persona;
      const v = validatePersona(validated);
      if (!v.valid) throw new Error(v.errors.join("; "));
      pushHistory(persona);
      setPersona(validated);
    } catch (err: any) {
      alert(`Invalid persona JSON: ${err?.message ?? String(err)}`);
    } finally {
      e.target.value = "";
    }
  };

  /** Генерация предпросмотра системного промпта */
  const systemPrompt = useMemo(() => {
    const lines: string[] = [];
    lines.push(`# Role: ${persona.role}`);
    if (persona.name) lines.push(`# Agent: ${persona.name}`);
    if (persona.description?.trim()) lines.push(`## Description:\n${persona.description.trim()}`);
    if (persona.tone) lines.push(`Tone: ${persona.tone}`);
    if (persona.style) lines.push(`Style: ${persona.style}`);
    if (persona.goals.length) {
      lines.push(`## Goals:`);
      persona.goals.forEach((g, i) => lines.push(`${i + 1}. ${g.text}`));
    }
    if (persona.skills.length) {
      lines.push(`## Skills:`);
      persona.skills.forEach((s) => lines.push(`- ${s.text}`));
    }
    if (persona.constraints.length) {
      lines.push(`## Constraints:`);
      persona.constraints.forEach((c) => lines.push(`- ${c.text}`));
    }
    if (persona.tools.length) {
      lines.push(`## Tools:`);
      persona.tools.forEach((t) => lines.push(`- ${t.name}: ${t.allowed ? "allowed" : "denied"}${t.note ? ` — ${t.note}` : ""}`));
    }
    lines.push(`## Safety:`);
    lines.push(`- browsing: ${persona.safety.allowBrowsing ? "on" : "off"}`);
    lines.push(`- code execution: ${persona.safety.allowCodeExec ? "on" : "off"}`);
    lines.push(`- max tokens: ${persona.safety.maxTokens}`);
    lines.push(`- temperature: ${persona.safety.temperature}`);
    return lines.join("\n");
  }, [persona]);

  /** Статус валидации */
  const validation = useMemo(() => validatePersona(persona), [persona]);

  /** Обработчики массивов */
  const addGoal = () => apply((p) => ({ ...p, goals: [...p.goals, { id: uuid(), text: "" }] }));
  const addSkill = () => apply((p) => ({ ...p, skills: [...p.skills, { id: uuid(), text: "" }] }));
  const addConstraint = () => apply((p) => ({ ...p, constraints: [...p.constraints, { id: uuid(), text: "" }] }));

  /** Подсказки-шаблоны */
  const goalTemplates = [
    "Deliver step-by-step reasoning for complex tasks.",
    "Prioritize factual accuracy with explicit sources.",
    "Propose safer alternatives if a user request is risky.",
  ];
  const skillTemplates = [
    "Decompose tasks into verifiable sub-steps.",
    "Summarize and compare multiple sources.",
    "Design experiments and evaluate results.",
  ];

  /** UI */
  return (
    <Card className={cn("w-full", className)} aria-label="Agent persona editor">
      <CardHeader className="flex flex-row items-center justify-between space-y-0">
        <div>
          <CardTitle className="leading-tight">{title}</CardTitle>
          <CardDescription className="mt-1">
            {description ?? "Настройка роли, целей, навыков, ограничений, доступов к инструментам и параметров безопасности агента. Автосохранение включено."}
          </CardDescription>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="secondary" size="sm" onClick={doExport} disabled={readOnly} title="Экспорт JSON">
            <IconDownload className="mr-2 h-4 w-4" /> Export
          </Button>
          <Button variant="secondary" size="sm" onClick={doImport} disabled={readOnly} title="Импорт JSON">
            <IconUpload className="mr-2 h-4 w-4" /> Import
          </Button>
          <input
            ref={fileInputRef}
            type="file"
            accept="application/json"
            className="hidden"
            onChange={onFileChange}
          />
          <Button variant="outline" size="sm" onClick={() => { pushHistory(persona); setPersona({ ...persona }); }} title="Сохранить снимок">
            <IconCopy className="mr-2 h-4 w-4" /> Snapshot
          </Button>
          <Button variant="outline" size="icon" onClick={doUndo} title="Undo" disabled={!undoStack.current.length}>
            <IconUndo className="h-4 w-4" />
          </Button>
          <Button variant="outline" size="icon" onClick={doRedo} title="Redo" disabled={!redoStack.current.length}>
            <IconRedo className="h-4 w-4" />
          </Button>
          <Button variant="outline" size="icon" onClick={resetToDefault} disabled={readOnly} title="Сбросить к дефолту">
            <IconRefresh className="h-4 w-4" />
          </Button>
        </div>
      </CardHeader>

      <CardContent className="space-y-6">
        {/* Базовые поля */}
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <div className="space-y-2">
            <Label htmlFor="agent-name">Name</Label>
            <Input
              id="agent-name"
              value={persona.name}
              onChange={(e) => apply({ name: e.target.value })}
              disabled={readOnly}
              placeholder="Phoenix Research Agent"
            />
          </div>

          <div className="space-y-2">
            <Label>Role</Label>
            <Select
              value={persona.role}
              onValueChange={(v) => apply({ role: v as Persona["role"] })}
              disabled={readOnly}
            >
              <SelectTrigger>
                <SelectDisplayValue placeholder="Select a role" />
              </SelectTrigger>
              <SelectContent>
                <SelectGroup>
                  <SelectGroupLabel>Common</SelectGroupLabel>
                  <SelectItem value="assistant">Assistant</SelectItem>
                  <SelectItem value="research">Research</SelectItem>
                  <SelectItem value="analyst">Analyst</SelectItem>
                  <SelectItem value="developer">Developer</SelectItem>
                  <SelectItem value="operations">Operations</SelectItem>
                </SelectGroup>
                <Separator className="my-1" />
                <SelectGroup>
                  <SelectGroupLabel>Other</SelectGroupLabel>
                  <SelectItem value="custom">Custom</SelectItem>
                </SelectGroup>
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label htmlFor="tone">Tone</Label>
            <Select
              value={persona.tone}
              onValueChange={(v) => apply({ tone: v as Persona["tone"] })}
              disabled={readOnly}
            >
              <SelectTrigger><SelectDisplayValue placeholder="Tone" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="neutral">Neutral</SelectItem>
                <SelectItem value="formal">Formal</SelectItem>
                <SelectItem value="friendly">Friendly</SelectItem>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="inquisitive">Inquisitive</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label htmlFor="style">Style</Label>
            <Select
              value={persona.style}
              onValueChange={(v) => apply({ style: v as Persona["style"] })}
              disabled={readOnly}
            >
              <SelectTrigger><SelectDisplayValue placeholder="Style" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="concise">Concise</SelectItem>
                <SelectItem value="balanced">Balanced</SelectItem>
                <SelectItem value="detailed">Detailed</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="md:col-span-2 space-y-2">
            <Label htmlFor="desc">Description</Label>
            <Textarea
              id="desc"
              rows={3}
              value={persona.description}
              onChange={(e: React.ChangeEvent<HTMLTextAreaElement>) => apply({ description: e.target.value })}
              disabled={readOnly}
              placeholder="Agent mission, domain, scope and non-goals."
            />
          </div>
        </div>

        <Separator />

        {/* Цели/навыки/ограничения */}
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <Label>Goals</Label>
              <Button variant="outline" size="icon" onClick={addGoal} disabled={readOnly} title="Add goal">
                <IconPlus className="h-4 w-4" />
              </Button>
            </div>
            <div className="space-y-2">
              {persona.goals.map((g, i) => (
                <EditableRow
                  key={g.id}
                  value={g.text}
                  onChange={(v) => apply((p) => ({ ...p, goals: p.goals.map((x) => (x.id === g.id ? { ...x, text: v } : x)) }))}
                  onDelete={() => apply((p) => ({ ...p, goals: p.goals.filter((x) => x.id !== g.id) }))}
                  placeholder={`Goal #${i + 1}`}
                />
              ))}
            </div>
            <div className="flex flex-wrap gap-2">
              {goalTemplates.map((t) => (
                <Badge
                  key={t}
                  variant="outline"
                  className="cursor-pointer"
                  onClick={() => apply((p) => ({ ...p, goals: [...p.goals, { id: uuid(), text: t }] }))}
                >
                  + {t}
                </Badge>
              ))}
            </div>
          </div>

          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <Label>Skills</Label>
              <Button variant="outline" size="icon" onClick={addSkill} disabled={readOnly} title="Add skill">
                <IconPlus className="h-4 w-4" />
              </Button>
            </div>
            <div className="space-y-2">
              {persona.skills.map((s, i) => (
                <EditableRow
                  key={s.id}
                  value={s.text}
                  onChange={(v) => apply((p) => ({ ...p, skills: p.skills.map((x) => (x.id === s.id ? { ...x, text: v } : x)) }))}
                  onDelete={() => apply((p) => ({ ...p, skills: p.skills.filter((x) => x.id !== s.id) }))}
                  placeholder={`Skill #${i + 1}`}
                />
              ))}
            </div>
            <div className="flex flex-wrap gap-2">
              {skillTemplates.map((t) => (
                <Badge
                  key={t}
                  variant="outline"
                  className="cursor-pointer"
                  onClick={() => apply((p) => ({ ...p, skills: [...p.skills, { id: uuid(), text: t }] }))}
                >
                  + {t}
                </Badge>
              ))}
            </div>
          </div>

          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <Label>Constraints</Label>
              <Button variant="outline" size="icon" onClick={addConstraint} disabled={readOnly} title="Add constraint">
                <IconPlus className="h-4 w-4" />
              </Button>
            </div>
            <div className="space-y-2">
              {persona.constraints.map((c, i) => (
                <EditableRow
                  key={c.id}
                  value={c.text}
                  onChange={(v) => apply((p) => ({ ...p, constraints: p.constraints.map((x) => (x.id === c.id ? { ...x, text: v } : x)) }))}
                  onDelete={() => apply((p) => ({ ...p, constraints: p.constraints.filter((x) => x.id !== c.id) }))}
                  placeholder={`Constraint #${i + 1}`}
                />
              ))}
            </div>
          </div>
        </div>

        <Separator />

        {/* Инструменты и безопасность */}
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <div className="space-y-3">
            <Label>Tools permissions</Label>
            <div className="space-y-3">
              {persona.tools.map((t, idx) => (
                <div key={t.name} className="grid grid-cols-1 items-center gap-2 sm:grid-cols-12">
                  <div className="sm:col-span-3">
                    <Input
                      value={t.name}
                      onChange={(e) => apply((p) => {
                        const copy = [...p.tools];
                        copy[idx] = { ...t, name: e.target.value };
                        return { ...p, tools: copy };
                      })}
                      disabled={readOnly}
                      placeholder="tool name"
                    />
                  </div>
                  <div className="sm:col-span-3 flex items-center gap-2">
                    <Switch
                      checked={t.allowed}
                      onCheckedChange={(v) => apply((p) => {
                        const copy = [...p.tools];
                        copy[idx] = { ...t, allowed: v };
                        return { ...p, tools: copy };
                      })}
                      id={`tool-${idx}`}
                      disabled={readOnly}
                    />
                    <Label htmlFor={`tool-${idx}`}>{t.allowed ? "allowed" : "denied"}</Label>
                  </div>
                  <div className="sm:col-span-5">
                    <Input
                      value={t.note ?? ""}
                      onChange={(e) => apply((p) => {
                        const copy = [...p.tools];
                        copy[idx] = { ...t, note: e.target.value };
                        return { ...p, tools: copy };
                      })}
                      disabled={readOnly}
                      placeholder="note"
                    />
                  </div>
                  <div className="sm:col-span-1 flex justify-end">
                    <Button
                      variant="outline"
                      size="icon"
                      onClick={() => apply((p) => ({ ...p, tools: p.tools.filter((_, i) => i !== idx) }))}
                      disabled={readOnly}
                      title="Delete tool"
                    >
                      <IconTrash className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              ))}
              <Button
                variant="secondary"
                size="sm"
                onClick={() => apply((p) => ({ ...p, tools: [...p.tools, { name: "", allowed: false }] }))}
                disabled={readOnly}
              >
                <IconPlus className="mr-2 h-4 w-4" />
                Add tool
              </Button>
            </div>
          </div>

          <div className="space-y-3">
            <Label>Safety & limits</Label>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div className="flex items-center gap-2">
                <Switch
                  checked={persona.safety.allowBrowsing}
                  onCheckedChange={(v) => apply({ safety: { ...persona.safety, allowBrowsing: v } })}
                  id="allow-browse"
                  disabled={readOnly}
                />
                <Label htmlFor="allow-browse">Allow browsing</Label>
              </div>
              <div className="flex items-center gap-2">
                <Switch
                  checked={persona.safety.allowCodeExec}
                  onCheckedChange={(v) => apply({ safety: { ...persona.safety, allowCodeExec: v } })}
                  id="allow-code"
                  disabled={readOnly}
                />
                <Label htmlFor="allow-code">Allow code exec</Label>
              </div>
              <div className="space-y-1">
                <Label htmlFor="max-tokens">Max tokens</Label>
                <Input
                  id="max-tokens"
                  inputMode="numeric"
                  value={persona.safety.maxTokens}
                  onChange={(e) => {
                    const n = Math.max(1, Number(e.target.value) || 1);
                    apply({ safety: { ...persona.safety, maxTokens: n } });
                  }}
                  disabled={readOnly}
                />
              </div>
              <div className="space-y-1">
                <Label htmlFor="temperature">Temperature</Label>
                <Input
                  id="temperature"
                  inputMode="decimal"
                  value={persona.safety.temperature}
                  onChange={(e) => {
                    let n = Number(e.target.value);
                    if (Number.isNaN(n)) n = 0.2;
                    n = Math.max(0, Math.min(2, n));
                    apply({ safety: { ...persona.safety, temperature: n } });
                  }}
                  disabled={readOnly}
                />
              </div>
            </div>
            <div className="text-xs text-muted-foreground">
              Limits: maxTokens {formatNumber(persona.safety.maxTokens)} · temperature {persona.safety.temperature}
            </div>
          </div>
        </div>

        <Separator />

        {/* Примеры */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <Label>Examples (title, input, output)</Label>
            <Button
              variant="outline"
              size="sm"
              onClick={() => apply((p) => ({
                ...p,
                examples: [...(p.examples ?? []), { title: "", input: "", output: "" }],
              }))}
              disabled={readOnly}
            >
              <IconPlus className="mr-2 h-4 w-4" /> Add example
            </Button>
          </div>

          <div className="space-y-4">
            {(persona.examples ?? []).map((ex, idx) => (
              <div key={idx} className="rounded-xl border p-3">
                <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                  <div className="space-y-1">
                    <Label>Title</Label>
                    <Input
                      value={ex.title}
                      onChange={(e) => apply((p) => {
                        const copy = [...(p.examples ?? [])];
                        copy[idx] = { ...copy[idx], title: e.target.value };
                        return { ...p, examples: copy };
                      })}
                      disabled={readOnly}
                    />
                  </div>
                  <div className="space-y-1">
                    <Label>Input</Label>
                    <Textarea
                      rows={2}
                      value={ex.input}
                      onChange={(e: React.ChangeEvent<HTMLTextAreaElement>) => apply((p) => {
                        const copy = [...(p.examples ?? [])];
                        copy[idx] = { ...copy[idx], input: e.target.value };
                        return { ...p, examples: copy };
                      })}
                      disabled={readOnly}
                    />
                  </div>
                  <div className="md:col-span-2 space-y-1">
                    <Label>Output</Label>
                    <Textarea
                      rows={2}
                      value={ex.output}
                      onChange={(e: React.ChangeEvent<HTMLTextAreaElement>) => apply((p) => {
                        const copy = [...(p.examples ?? [])];
                        copy[idx] = { ...copy[idx], output: e.target.value };
                        return { ...p, examples: copy };
                      })}
                      disabled={readOnly}
                    />
                  </div>
                </div>
                <div className="mt-2 flex justify-end">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => apply((p) => {
                      const copy = [...(p.examples ?? [])];
                      copy.splice(idx, 1);
                      return { ...p, examples: copy };
                    })}
                    disabled={readOnly}
                  >
                    <IconTrash className="mr-2 h-4 w-4" /> Remove
                  </Button>
                </div>
              </div>
            ))}
          </div>
        </div>

        <Separator />

        {/* Просмотр/экспорт системного промпта и JSON */}
        <Tabs defaultValue="prompt">
          <TabsList className="grid grid-cols-3">
            <TabsTrigger value="prompt">System prompt</TabsTrigger>
            <TabsTrigger value="json">JSON</TabsTrigger>
            <TabsTrigger value="validate">Validation</TabsTrigger>
          </TabsList>

          <TabsContent value="prompt" className="space-y-2">
            <div className="rounded-xl border p-3 text-sm whitespace-pre-wrap leading-6 min-h-[180px] bg-muted/20">
              {systemPrompt}
            </div>
            <div className="flex gap-2">
              <Button
                variant="secondary"
                size="sm"
                onClick={async () => await navigator.clipboard.writeText(systemPrompt)}
              >
                <IconCopy className="mr-2 h-4 w-4" /> Copy prompt
              </Button>
              <Button variant="secondary" size="sm" onClick={() => downloadBlob(systemPrompt, "system_prompt.txt", "text/plain;charset=utf-8")}>
                <IconDownload className="mr-2 h-4 w-4" /> Download .txt
              </Button>
            </div>
          </TabsContent>

          <TabsContent value="json" className="space-y-2">
            <Textarea
              className="font-mono text-xs"
              rows={14}
              value={JSON.stringify(persona, null, 2)}
              onChange={(e: React.ChangeEvent<HTMLTextAreaElement>) => {
                if (readOnly) return;
                try {
                  const parsed = JSON.parse(e.target.value) as Persona;
                  const v = validatePersona({ ...DEFAULT_PERSONA, ...parsed });
                  if (!v.valid) return; // мягкий отказ, чтобы не ломать состояние
                  pushHistory(persona);
                  setPersona({ ...DEFAULT_PERSONA, ...parsed });
                } catch {
                  // игнорируем до валидного JSON
                }
              }}
              disabled={readOnly}
            />
            <div className="flex gap-2">
              <Button variant="secondary" size="sm" onClick={doExport}>
                <IconDownload className="mr-2 h-4 w-4" /> Download JSON
              </Button>
            </div>
          </TabsContent>

          <TabsContent value="validate" className="space-y-2">
            {validation.valid ? (
              <div className="rounded-xl border p-3 text-sm text-emerald-700 dark:text-emerald-300 bg-emerald-500/10">
                Persona is valid.
              </div>
            ) : (
              <div className="space-y-2">
                {validation.errors.map((e, i) => (
                  <div key={i} className="rounded-xl border p-3 text-sm text-rose-700 dark:text-rose-300 bg-rose-500/10">
                    {e}
                  </div>
                ))}
              </div>
            )}
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
};

export default AgentPersonaEditor;
