// frontend/src/pages/ZKVoteInterface.tsx

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
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  ShieldCheck, UploadCloud, CheckCircle2, XCircle, FileJson, Hash, Loader2, Database, Activity,
  Vote as VoteIcon, LockKeyhole, BarChart3, Info, RefreshCcw, Network, Wallet, Eye
} from "lucide-react";
import {
  Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip as RTooltip, XAxis, YAxis
} from "recharts";

// --------------------------- Types ---------------------------

type NetworkHealth = {
  network: string;
  chainId: number;
  relayerOnline: boolean;
  verifierOnline: boolean;
  indexRoot: string;
  schemaVersion: string;
  timestamp: string; // ISO
};

type Proposal = {
  id: string;
  title: string;
  description: string;
  options: string[];
  deadline: string; // ISO
};

type VerificationInput = {
  proofJson: unknown;
  signal?: string;
};

type VerificationResult = {
  ok: boolean;
  proofHash: string;
  nullifier: string;
  commitment: string;
  verifiedAt: string; // ISO
  warnings?: string[];
  errors?: string[];
};

type SubmitVoteResult = {
  accepted: boolean;
  txId?: string;
  receivedAt: string;
  reason?: string;
};

type TallyRow = { option: string; votes: number; percent: number };
type Tally = {
  proposalId: string;
  total: number;
  rows: TallyRow[];
  merkleRoot: string;
  nullifierSetSize: number;
  lastUpdated: string; // ISO
};

type ApiError = { message: string; status?: number; code?: string };

// --------------------------- API Layer ---------------------------

class ZKVoteApi {
  private base = "/api/zkvote";
  constructor(private fetcher: typeof fetch = fetch) {}

  async getHealth(signal?: AbortSignal): Promise<NetworkHealth> {
    const res = await this.fetcher(`${this.base}/health`, { signal });
    if (!res.ok) throw await this.err(res);
    return res.json();
  }

  async getProposal(signal?: AbortSignal): Promise<Proposal> {
    const res = await this.fetcher(`${this.base}/proposal`, { signal });
    if (!res.ok) throw await this.err(res);
    return res.json();
  }

  async verifyProof(input: VerificationInput, signal?: AbortSignal): Promise<VerificationResult> {
    const res = await this.fetcher(`${this.base}/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(input),
      signal,
    });
    if (!res.ok) throw await this.err(res);
    return res.json();
  }

  async submitVote(payload: {
    proposalId: string;
    option: string;
    nullifier: string;
    commitment: string;
    proof: unknown;
    memo?: string;
  }, signal?: AbortSignal): Promise<SubmitVoteResult> {
    const res = await this.fetcher(`${this.base}/vote`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal,
    });
    if (!res.ok) throw await this.err(res);
    return res.json();
  }

  async fetchTally(signal?: AbortSignal): Promise<Tally> {
    const res = await this.fetcher(`${this.base}/tally`, { signal });
    if (!res.ok) throw await this.err(res);
    return res.json();
  }

  private async err(res: Response): Promise<ApiError> {
    let message = `HTTP ${res.status}`;
    try {
      const data = await res.json();
      message = data?.message || data?.error || message;
    } catch { /* noop */ }
    return { message, status: res.status };
  }
}

const api = new ZKVoteApi();

// --------------------------- Form Schemas ---------------------------

const proofSchema = z.object({
  // mutually exclusive: either file or text
  proofText: z.string().optional(),
  signal: z.string().max(256, "Сигнал слишком длинный").optional(),
  acceptWarnings: z.boolean().default(false),
});

type ProofForm = z.infer<typeof proofSchema>;

const voteSchema = z.object({
  option: z.string().min(1, "Выберите вариант"),
  nullifier: z.string().min(8, "Nullifier слишком короткий"),
  commitment: z.string().min(8, "Commitment слишком короткий"),
  memo: z.string().max(500).optional(),
});
type VoteForm = z.infer<typeof voteSchema>;

// --------------------------- Helpers ---------------------------

function prettyISO(iso?: string) {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleString();
}

function bytesToJsonSafe(text: string): unknown {
  // Accept plain JSON or hex-encoded JSON (0x...)
  const trimmed = text.trim();
  if (!trimmed) throw new Error("Пустой ввод доказательства");
  if (trimmed.startsWith("{")) return JSON.parse(trimmed);
  if (trimmed.startsWith("0x")) {
    const hex = trimmed.slice(2);
    const bytes = new Uint8Array(hex.match(/.{1,2}/g)!.map((b) => parseInt(b, 16)));
    const json = new TextDecoder().decode(bytes);
    return JSON.parse(json);
  }
  // Try base64
  try {
    const json = atob(trimmed);
    return JSON.parse(json);
  } catch {
    // fallback: try as JSON anyway
    return JSON.parse(trimmed);
  }
}

function percent(n: number, total: number): number {
  return total > 0 ? Math.round((n / total) * 1000) / 10 : 0;
}

// --------------------------- Main Component ---------------------------

const ZKVoteInterface: React.FC = () => {
  const [health, setHealth] = useState<NetworkHealth | null>(null);
  const [proposal, setProposal] = useState<Proposal | null>(null);
  const [tally, setTally] = useState<Tally | null>(null);

  const [loadingHealth, setLoadingHealth] = useState(true);
  const [loadingProposal, setLoadingProposal] = useState(true);
  const [loadingTally, setLoadingTally] = useState(true);

  const [globalError, setGlobalError] = useState<string | null>(null);

  const abortRef = useRef<AbortController | null>(null);

  // Proof form state
  const [proofForm, setProofForm] = useState<ProofForm>({
    proofText: '',
    signal: '',
    acceptWarnings: false
  });
  const [proofErrors, setProofErrors] = useState<Record<string, string>>({});

  // Vote form state  
  const [voteForm, setVoteForm] = useState<VoteForm>({
    option: '',
    nullifier: '',
    commitment: '',
    memo: ''
  });
  const [voteErrors, setVoteErrors] = useState<Record<string, string>>({});
  const [isVoting, setIsVoting] = useState(false);

  const [verifying, setVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState<VerificationResult | null>(null);
  const [verifyError, setVerifyError] = useState<string | null>(null);

  const [submitting, setSubmitting] = useState(false);
  const [submitResult, setSubmitResult] = useState<SubmitVoteResult | null>(null);
  const [submitError, setSubmitError] = useState<string | null>(null);

  const [proofFileName, setProofFileName] = useState<string>("");

  const isDeadlinePassed = useMemo(() => {
    if (!proposal?.deadline) return false;
    return new Date(proposal.deadline).getTime() < Date.now();
  }, [proposal]);

  // Initial load
  useEffect(() => {
    const ac = new AbortController();
    abortRef.current = ac;

    setLoadingHealth(true);
    setLoadingProposal(true);
    setLoadingTally(true);
    setGlobalError(null);

    Promise.allSettled([
      api.getHealth(ac.signal),
      api.getProposal(ac.signal),
      api.fetchTally(ac.signal),
    ]).then((results) => {
      const [h, p, t] = results;
      if (h.status === "fulfilled") setHealth(h.value); else setGlobalError(h.reason?.message || "Ошибка загрузки статуса сети");
      if (p.status === "fulfilled") setProposal(p.value); else setGlobalError(p.reason?.message || "Ошибка загрузки предложения");
      if (t.status === "fulfilled") setTally(t.value); else setGlobalError(t.reason?.message || "Ошибка загрузки итогов");
    }).finally(() => {
      setLoadingHealth(false);
      setLoadingProposal(false);
      setLoadingTally(false);
    });

    return () => ac.abort();
  }, []);

  const onUploadProofFile = useCallback(async (file: File) => {
    setVerifyResult(null);
    setVerifyError(null);
    setProofFileName(file.name);
    if (file.size > 2 * 1024 * 1024) {
      setVerifyError("Файл слишком большой (>2MB)");
      return;
    }
    const text = await file.text();
    setProofForm(prev => ({ ...prev, proofText: text }));
  }, []);

  const doVerify = useCallback(async (form: ProofForm) => {
    setVerifying(true);
    setVerifyError(null);
    setVerifyResult(null);
    setSubmitResult(null);
    setSubmitError(null);

    try {
      const proofJson = bytesToJsonSafe(form.proofText || "");
      const res = await api.verifyProof({ proofJson, signal: form.signal });
      setVerifyResult(res);

      // Prime vote form with artifacts
      setVoteForm(prev => ({ ...prev, nullifier: res.nullifier, commitment: res.commitment }));
    } catch (e: any) {
      setVerifyError(e?.message || "Не удалось верифицировать доказательство");
    } finally {
      setVerifying(false);
    }
  }, []);

  const refreshTally = useCallback(async () => {
    setLoadingTally(true);
    setGlobalError(null);
    try {
      const res = await api.fetchTally();
      setTally(res);
    } catch (e: any) {
      setGlobalError(e?.message || "Ошибка обновления итогов");
    } finally {
      setLoadingTally(false);
    }
  }, []);

  const doSubmitVote = useCallback(async (data: VoteForm) => {
    if (!proposal) return;
    if (!verifyResult?.ok) {
      setSubmitError("Сначала пройдите проверку доказательства");
      return;
    }
    setSubmitting(true);
    setSubmitError(null);
    setSubmitResult(null);

    try {
      // We reuse the proofText already parsed earlier for submission consistency
      const proofText = proofForm.proofText;
      const proofJson = bytesToJsonSafe(proofText || "");
      const res = await api.submitVote({
        proposalId: proposal.id,
        option: data.option,
        nullifier: data.nullifier,
        commitment: data.commitment,
        proof: proofJson,
        memo: data.memo,
      });
      setSubmitResult(res);
      if (res.accepted) {
        // clear only memo/option; keep artifacts to allow re-checks
        setVoteForm({ option: "", nullifier: verifyResult.nullifier, commitment: verifyResult.commitment, memo: "" });
        await refreshTally();
      }
    } catch (e: any) {
      setSubmitError(e?.message || "Не удалось отправить голос");
    } finally {
      setSubmitting(false);
    }
  }, [proposal, verifyResult, refreshTally]);

  const chartData = useMemo(() => {
    if (!tally) return [];
    return tally.rows.map(r => ({ option: r.option, votes: r.votes, percent: r.percent }));
  }, [tally]);

  // --------------------------- Render ---------------------------

  return (
    <div className="container mx-auto max-w-6xl p-6 space-y-6">
      <header className="flex items-start justify-between gap-4">
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5" />
            <h1 className="text-2xl font-semibold tracking-tight">ZK-Голосование</h1>
            {loadingHealth ? (
              <Badge variant="secondary" className="ml-2"><Loader2 className="mr-1 h-3 w-3 animate-spin" />Загрузка сети</Badge>
            ) : health?.verifierOnline && health?.relayerOnline ? (
              <Badge className="ml-2" variant="default">Готово к работе</Badge>
            ) : (
              <Badge className="ml-2" variant="destructive">Сервис недоступен</Badge>
            )}
          </div>
          <p className="text-muted-foreground">Интерфейс нулевого разглашения с проверкой доказательств, анонимной подачей голосов и публичным аудитом итогов.</p>
        </div>

        <Card className="min-w-[320px]">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-base">
              <Network className="h-4 w-4" />
              Сеть и статус
            </CardTitle>
            <CardDescription>Онлайн-проверки и индекс</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {loadingHealth ? (
              <>
                <Skeleton className="h-4 w-full" />
                <Skeleton className="h-4 w-3/4" />
                <Skeleton className="h-4 w-2/3" />
              </>
            ) : health ? (
              <>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Сеть</span>
                  <span className="text-sm font-medium">{health.network} (chainId {health.chainId})</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Verifier</span>
                  <span className="text-sm font-medium">{health.verifierOnline ? "online" : "offline"}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Relayer</span>
                  <span className="text-sm font-medium">{health.relayerOnline ? "online" : "offline"}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Index root</span>
                  <span className="text-sm font-mono">{short(health.indexRoot)}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Schema</span>
                  <span className="text-sm font-medium">{health.schemaVersion}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Обновлено</span>
                  <span className="text-sm">{prettyISO(health.timestamp)}</span>
                </div>
              </>
            ) : (
              <Alert variant="destructive">
                <AlertTitle>Ошибка</AlertTitle>
                <AlertDescription>Не удалось получить статус сети.</AlertDescription>
              </Alert>
            )}
          </CardContent>
        </Card>
      </header>

      <main className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <section className="lg:col-span-2 space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <VoteIcon className="h-5 w-5" />
                {loadingProposal ? "Загрузка предложения..." : (proposal?.title || "Предложение")}
                {isDeadlinePassed && <Badge variant="secondary" className="ml-2">Голосование завершено</Badge>}
              </CardTitle>
              <CardDescription>
                {loadingProposal ? <Skeleton className="h-4 w-64" /> : proposal?.description || "—"}
              </CardDescription>
            </CardHeader>
            <CardContent className="text-sm text-muted-foreground flex items-center gap-4">
              <div className="flex items-center gap-2">
                <Activity className="h-4 w-4" />
                ID: <span className="font-mono">{proposal?.id || "—"}</span>
              </div>
              <Separator orientation="vertical" />
              <div className="flex items-center gap-2">
                <Eye className="h-4 w-4" />
                Дедлайн: {proposal?.deadline ? prettyISO(proposal.deadline) : "—"}
              </div>
            </CardContent>
          </Card>

          <Tabs defaultValue="verify" className="w-full">
            <TabsList className="grid grid-cols-3">
              <TabsTrigger value="verify" className="flex items-center gap-2">
                <ShieldCheck className="h-4 w-4" /> Проверка доказательства
              </TabsTrigger>
              <TabsTrigger value="vote" className="flex items-center gap-2" disabled={isDeadlinePassed}>
                <LockKeyhole className="h-4 w-4" /> Отдать голос
              </TabsTrigger>
              <TabsTrigger value="tally" className="flex items-center gap-2">
                <BarChart3 className="h-4 w-4" /> Итоги и аудит
              </TabsTrigger>
            </TabsList>

            {/* Verify */}
            <TabsContent value="verify" className="mt-4">
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Загрузка/вставка доказательства</CardTitle>
                  <CardDescription>Поддерживаются JSON, 0x-hex или base64</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid gap-4">
                    <div className="grid gap-2">
                      <Label htmlFor="proof-file" className="flex items-center gap-2">
                        <FileJson className="h-4 w-4" />
                        Файл доказательства (.json)
                      </Label>
                      <div className="flex items-center gap-2">
                        <Input id="proof-file" type="file" accept=".json,application/json"
                          onChange={(e) => {
                            const f = e.target.files?.[0];
                            if (f) onUploadProofFile(f);
                          }}
                        />
                        <TooltipProvider>
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <Button type="button" variant="secondary" onClick={() => {
                                setProofFileName("");
                                setProofForm(prev => ({ ...prev, proofText: "" }));
                                setVerifyResult(null);
                                setVerifyError(null);
                              }}>
                                Очистить
                              </Button>
                            </TooltipTrigger>
                            <TooltipContent>Удалить файл и ввод</TooltipContent>
                          </Tooltip>
                        </TooltipProvider>
                      </div>
                      {proofFileName && <p className="text-xs text-muted-foreground">Выбран файл: {proofFileName}</p>}
                    </div>

                    <div className="grid gap-2">
                      <Label htmlFor="proofText">Или вставьте JSON/hex/base64</Label>
                      <Textarea id="proofText" rows={8} placeholder='{"pi_a": "...", ...}'
                        value={proofForm.proofText}
                        onChange={(e) => setProofForm(prev => ({ ...prev, proofText: e.target.value }))}
                      />
                      {proofErrors.proofText && <p className="text-xs text-destructive">{proofErrors.proofText}</p>}
                    </div>

                    <div className="grid gap-2">
                      <Label htmlFor="signal" className="flex items-center gap-2">
                        <Hash className="h-4 w-4" />
                        Связанный сигнал (необязательно)
                      </Label>
                      <Input 
                        id="signal" 
                        placeholder="Напр. идентификатор предложения, цепочки, комнаты" 
                        value={proofForm.signal}
                        onChange={(e) => setProofForm(prev => ({ ...prev, signal: e.target.value }))}
                      />
                    </div>

                    <div className="flex items-center justify-between rounded-lg border p-3">
                      <div className="space-y-1">
                        <p className="text-sm font-medium">Игнорировать предупреждения верификатора</p>
                        <p className="text-xs text-muted-foreground">Если отмечено, минорные предупреждения не блокируют проверку</p>
                      </div>
                      <Switch 
                        checked={proofForm.acceptWarnings}
                        onCheckedChange={(checked) => setProofForm(prev => ({ ...prev, acceptWarnings: checked }))}
                      />
                    </div>
                  </div>
                </CardContent>
                <CardFooter className="flex items-center justify-between">
                  <Button
                    onClick={() => doVerify(proofForm)}
                    disabled={verifying}
                    className="gap-2"
                  >
                    {verifying ? <Loader2 className="h-4 w-4 animate-spin" /> : <UploadCloud className="h-4 w-4" />}
                    Проверить
                  </Button>

                  {verifyResult?.ok && (
                    <Badge variant="default" className="flex items-center gap-1">
                      <CheckCircle2 className="h-3 w-3" /> Доказательство валидно
                    </Badge>
                  )}
                </CardFooter>

                {(verifyError || verifyResult) && (
                  <div className="px-6 pb-6">
                    {verifyError && (
                      <Alert variant="destructive" className="mb-4">
                        <AlertTitle className="flex items-center gap-2"><XCircle className="h-4 w-4" />Ошибка верификации</AlertTitle>
                        <AlertDescription className="text-sm">{verifyError}</AlertDescription>
                      </Alert>
                    )}
                    {verifyResult && (
                      <Card className="border-dashed">
                        <CardHeader>
                          <CardTitle className="text-sm">Результат верификации</CardTitle>
                          <CardDescription>Артефакты, необходимые для голосования</CardDescription>
                        </CardHeader>
                        <CardContent className="grid gap-2">
                          <MetaRow label="Хэш доказательства" value={verifyResult.proofHash} />
                          <MetaRow label="Nullifier" value={verifyResult.nullifier} />
                          <MetaRow label="Commitment" value={verifyResult.commitment} />
                          <MetaRow label="Время проверки" value={prettyISO(verifyResult.verifiedAt)} />
                          {verifyResult.warnings?.length ? (
                            <div className="rounded-md border p-3">
                              <p className="text-xs font-medium mb-2">Предупреждения:</p>
                              <ul className="list-disc pl-5 text-xs text-muted-foreground space-y-1">
                                {verifyResult.warnings.map((w, i) => <li key={i}>{w}</li>)}
                              </ul>
                            </div>
                          ) : null}
                          {verifyResult.errors?.length ? (
                            <div className="rounded-md border p-3">
                              <p className="text-xs font-medium mb-2">Замечания:</p>
                              <ul className="list-disc pl-5 text-xs text-muted-foreground space-y-1">
                                {verifyResult.errors.map((w, i) => <li key={i}>{w}</li>)}
                              </ul>
                            </div>
                          ) : null}
                        </CardContent>
                      </Card>
                    )}
                  </div>
                )}
              </Card>
            </TabsContent>

            {/* Vote */}
            <TabsContent value="vote" className="mt-4">
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Отправка анонимного голоса</CardTitle>
                  <CardDescription>Требуется валидное доказательство (вкладка «Проверка доказательства»)</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  {isDeadlinePassed && (
                    <Alert variant="destructive">
                      <AlertTitle>Срок истек</AlertTitle>
                      <AlertDescription>Голосование уже завершено, отправка недоступна.</AlertDescription>
                    </Alert>
                  )}

                  {!verifyResult?.ok && !isDeadlinePassed && (
                    <Alert>
                      <AlertTitle>Требуется проверка</AlertTitle>
                      <AlertDescription>Сначала загрузите и проверьте доказательство, после чего артефакты подставятся автоматически.</AlertDescription>
                    </Alert>
                  )}

                  <div className="grid sm:grid-cols-2 gap-4">
                    <div className="grid gap-2">
                      <Label>Вариант</Label>
                      <Select
                        onValueChange={(v) => setVoteForm(prev => ({ ...prev, option: v }))}
                        disabled={!proposal || isDeadlinePassed}
                      >
                        <SelectTrigger>
                          <SelectValue placeholder="Выберите..." />
                        </SelectTrigger>
                        <SelectContent>
                          {proposal?.options.map((opt) => (
                            <SelectItem key={opt} value={opt}>{opt}</SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                      {voteErrors.option && <p className="text-xs text-destructive">{voteErrors.option}</p>}
                    </div>

                    <div className="grid gap-2">
                      <Label htmlFor="nullifier">Nullifier</Label>
                      <Input 
                        id="nullifier" 
                        placeholder="Подставится после верификации" 
                        value={voteForm.nullifier}
                        onChange={(e) => setVoteForm(prev => ({ ...prev, nullifier: e.target.value }))}
                      />
                      {voteErrors.nullifier && <p className="text-xs text-destructive">{voteErrors.nullifier}</p>}
                    </div>

                    <div className="grid gap-2">
                      <Label htmlFor="commitment">Commitment</Label>
                      <Input 
                        id="commitment" 
                        placeholder="Подставится после верификации" 
                        value={voteForm.commitment}
                        onChange={(e) => setVoteForm(prev => ({ ...prev, commitment: e.target.value }))}
                      />
                      {voteErrors.commitment && <p className="text-xs text-destructive">{voteErrors.commitment}</p>}
                    </div>

                    <div className="grid gap-2 sm:col-span-2">
                      <Label htmlFor="memo">Комментарий (необязательно)</Label>
                      <Textarea id="memo" rows={3} placeholder="Короткая заметка (не публикуется)"
                        value={voteForm.memo}
                        onChange={(e) => setVoteForm(prev => ({ ...prev, memo: e.target.value }))}
                      />
                    </div>
                  </div>
                </CardContent>
                <CardFooter className="flex items-center justify-between">
                  <Button
                    className="gap-2"
                    disabled={isDeadlinePassed || !verifyResult?.ok || submitting || isVoting}
                    onClick={() => doSubmitVote(voteForm)}
                  >
                    {submitting ? <Loader2 className="h-4 w-4 animate-spin" /> : <Wallet className="h-4 w-4" />}
                    Отправить голос
                  </Button>

                  {submitResult?.accepted && (
                    <Badge variant="default" className="flex items-center gap-1">
                      <CheckCircle2 className="h-3 w-3" /> Принято
                    </Badge>
                  )}
                </CardFooter>

                {(submitError || submitResult) && (
                  <div className="px-6 pb-6">
                    {submitError && (
                      <Alert variant="destructive" className="mb-4">
                        <AlertTitle className="flex items-center gap-2"><XCircle className="h-4 w-4" />Ошибка отправки</AlertTitle>
                        <AlertDescription className="text-sm">{submitError}</AlertDescription>
                      </Alert>
                    )}
                    {submitResult && (
                      <Card className="border-dashed">
                        <CardHeader>
                          <CardTitle className="text-sm">Подтверждение</CardTitle>
                          <CardDescription>Результат приема голоса сервером</CardDescription>
                        </CardHeader>
                        <CardContent className="grid gap-2">
                          <MetaRow label="Статус" value={submitResult.accepted ? "Принято" : "Отклонено"} />
                          <MetaRow label="TxID" value={submitResult.txId || "—"} />
                          <MetaRow label="Время" value={prettyISO(submitResult.receivedAt)} />
                          {submitResult.reason && <MetaRow label="Причина" value={submitResult.reason} />}
                        </CardContent>
                      </Card>
                    )}
                  </div>
                )}
              </Card>
            </TabsContent>

            {/* Tally */}
            <TabsContent value="tally" className="mt-4">
              <Card>
                <CardHeader className="flex flex-col gap-1">
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle className="text-base">Итоги и аудит</CardTitle>
                      <CardDescription>Публичные агрегаты без разглашения личности</CardDescription>
                    </div>
                    <Button variant="secondary" className="gap-2" onClick={refreshTally} disabled={loadingTally}>
                      {loadingTally ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCcw className="h-4 w-4" />}
                      Обновить
                    </Button>
                  </div>
                </CardHeader>
                <CardContent className="space-y-6">
                  {loadingTally ? (
                    <div className="space-y-2">
                      <Skeleton className="h-6 w-40" />
                      <Progress value={45} />
                      <Skeleton className="h-64 w-full" />
                    </div>
                  ) : tally ? (
                    <>
                      <div className="grid sm:grid-cols-4 gap-4">
                        <Stat title="Всего голосов" value={tally.total.toString()} icon={<Database className="h-4 w-4" />} />
                        <Stat title="Nullifier-набор" value={tally.nullifierSetSize.toString()} icon={<LockKeyhole className="h-4 w-4" />} />
                        <Stat title="Merkle root" value={short(tally.merkleRoot)} icon={<Hash className="h-4 w-4" />} mono />
                        <Stat title="Обновлено" value={prettyISO(tally.lastUpdated)} icon={<Activity className="h-4 w-4" />} />
                      </div>

                      <div className="h-[320px] w-full">
                        <ResponsiveContainer width="100%" height="100%">
                          <BarChart data={chartData}>
                            <CartesianGrid strokeDasharray="3 3" />
                            <XAxis dataKey="option" />
                            <YAxis />
                            <RTooltip />
                            <Legend />
                            <Bar dataKey="votes" name="Голоса" />
                          </BarChart>
                        </ResponsiveContainer>
                      </div>

                      <div className="rounded-md border">
                        <div className="grid grid-cols-12 px-4 py-2 text-xs font-medium text-muted-foreground">
                          <div className="col-span-6">Вариант</div>
                          <div className="col-span-3 text-right">Голоса</div>
                          <div className="col-span-3 text-right">% от общего</div>
                        </div>
                        <Separator />
                        {tally.rows.map((r) => (
                          <div key={r.option} className="grid grid-cols-12 px-4 py-2 text-sm">
                            <div className="col-span-6">{r.option}</div>
                            <div className="col-span-3 text-right font-mono">{r.votes}</div>
                            <div className="col-span-3 text-right">{r.percent.toFixed(1)}%</div>
                          </div>
                        ))}
                      </div>
                    </>
                  ) : (
                    <Alert variant="destructive">
                      <AlertTitle>Нет данных</AlertTitle>
                      <AlertDescription>Итоги недоступны. Попробуйте обновить позже.</AlertDescription>
                    </Alert>
                  )}
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </section>

        {/* Side panel */}
        <aside className="space-y-6">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base">Памятка приватности</CardTitle>
              <CardDescription>Как работает ZK-анонимность</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3 text-sm text-muted-foreground">
              <p className="flex items-start gap-2">
                <Info className="mt-0.5 h-4 w-4" />
                Верификатор проверяет корректность доказательства без раскрытия личности, а nullifier предотвращает повторное голосование.
              </p>
              <p className="flex items-start gap-2">
                <Info className="mt-0.5 h-4 w-4" />
                Commitment доказывает принадлежность к набору избирателей, не раскрывая исходные атрибуты.
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base">Быстрый аудит</CardTitle>
              <CardDescription>Технические метаданные</CardDescription>
            </CardHeader>
            <CardContent className="space-y-2 text-sm">
              <MetaRow label="Сеть" value={health?.network || "—"} />
              <MetaRow label="ChainId" value={health?.chainId?.toString() || "—"} />
              <MetaRow label="Index root" value={health?.indexRoot || "—"} />
              <MetaRow label="Schema" value={health?.schemaVersion || "—"} />
              <MetaRow label="Deadline" value={proposal?.deadline ? prettyISO(proposal.deadline) : "—"} />
            </CardContent>
          </Card>
        </aside>
      </main>

      {globalError && (
        <Alert variant="destructive">
          <AlertTitle>Системная ошибка</AlertTitle>
          <AlertDescription>{globalError}</AlertDescription>
        </Alert>
      )}
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

function Stat({ title, value, icon, mono = false }: { title: string; value: string; icon?: React.ReactNode; mono?: boolean }) {
  return (
    <div className="rounded-lg border p-3">
      <div className="flex items-center gap-2 text-xs text-muted-foreground mb-1">
        {icon}
        {title}
      </div>
      <div className={`text-sm ${mono ? "font-mono" : "font-semibold"}`}>{value}</div>
    </div>
  );
}

function short(s?: string, head = 8, tail = 6) {
  if (!s) return "—";
  if (s.length <= head + tail + 3) return s;
  return `${s.slice(0, head)}...${s.slice(-tail)}`;
}

export default ZKVoteInterface;
