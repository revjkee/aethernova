// frontend/src/pages/DAOGovernance.tsx
// Industrial-grade DAO Governance Panel
// Assumes presence of TailwindCSS, shadcn/ui, lucide-react, recharts, framer-motion.
// If your project paths differ, adjust "@/components/ui/*" imports accordingly.

import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { motion } from "framer-motion";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Download,
  Filter,
  Gavel,
  LineChart as LineChartIcon,
  Plus,
  PlugZap,
  RefreshCw,
  Shield,
  Users2,
} from "lucide-react";
import {
  ResponsiveContainer,
  LineChart,
  Line,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
  BarChart,
  Bar,
} from "recharts";

// shadcn/ui components (adjust to your setup)
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Switch } from "@/components/ui/switch";
import { Separator } from "@/components/ui/separator";
import { useToast } from "@/components/ui/use-toast";

// ---------- Types ----------
type ProposalState = "Pending" | "Active" | "Succeeded" | "Defeated" | "Queued" | "Executed" | "Canceled";

type Proposal = {
  id: string;
  title: string;
  description: string;
  proposer: string;
  state: ProposalState;
  startTime: string; // ISO
  endTime: string;   // ISO
  forVotes: string;  // numeric string
  againstVotes: string;
  abstainVotes: string;
  quorum: string;
  eta?: string; // ISO for execution if queued
};

type GovernanceMetrics = {
  totalProposals: number;
  activeProposals: number;
  voterTurnoutPct: number;
  avgQuorumPct: number;
};

type SeriesPoint = { t: string; proposals: number; votes: number; turnoutPct: number };
type VoteBreakdown = { day: string; for: number; against: number; abstain: number };

type Wallet = {
  connected: boolean;
  address?: `0x${string}`;
  chainId?: string; // hex
  balanceWei?: string; // hex
};

type CreateProposalPayload = {
  title: string;
  description: string;
  actionsJson: string; // JSON string describing actions {targets, values, signatures/calldatas}
  votingDelay: number;   // blocks or seconds, decided backend
  votingPeriod: number;  // blocks or seconds
  metadata?: Record<string, any>;
};

type CastVotePayload = {
  proposalId: string;
  support: 0 | 1 | 2; // against/for/abstain
  reason?: string;
  voter?: string;
  signature?: string; // personal_sign signature
  nonce?: string;
};

// ---------- Constants ----------
const API_BASE = "/api/dao";
const WS_URL = ((): string => {
  if (typeof window === "undefined") return "";
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  return `${proto}://${window.location.host}/ws/dao`;
})();

const LOG_LIMIT = 1200;
const PAGE_SIZE = 25;

// Simple date formatting function to replace date-fns
function formatDate(date: Date, formatStr: string): string {
  if (formatStr === "yyyy-MM-dd HH:mm") {
    return date.toISOString().replace('T', ' ').slice(0, 16);
  }
  
  // Fallback
  return date.toISOString();
}

// ---------- Utilities ----------
function cn(...cls: Array<string | false | undefined>) {
  return cls.filter(Boolean).join(" ");
}
function useDebounced<T>(value: T, delay = 300): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const id = setTimeout(() => setV(value), delay);
    return () => clearTimeout(id);
  }, [value, delay]);
  return v;
}
function usePersistedState<T>(key: string, initial: T) {
  const [state, setState] = useState<T>(() => {
    try {
      const raw = localStorage.getItem(key);
      return raw ? (JSON.parse(raw) as T) : initial;
    } catch {
      return initial;
    }
  });
  useEffect(() => {
    try {
      localStorage.setItem(key, JSON.stringify(state));
    } catch {}
  }, [key, state]);
  return [state, setState] as const;
}
function shortTime(iso: string) {
  try {
    const d = new Date(iso);
    const hh = String(d.getHours()).padStart(2, "0");
    const mm = String(d.getMinutes()).padStart(2, "0");
    return `${hh}:${mm}`;
  } catch {
    return iso;
  }
}

// ---------- Hooks ----------
function useWallet(): {
  wallet: Wallet;
  connect: () => Promise<void>;
  signMessage: (message: string) => Promise<string>;
} {
  const [wallet, setWallet] = useState<Wallet>({ connected: false });

  const connect = useCallback(async () => {
    const eth = (window as any).ethereum;
    if (!eth) throw new Error("Кошелек EIP-1193 не обнаружен");
    const accounts: string[] = await eth.request({ method: "eth_requestAccounts" });
    const chainId: string = await eth.request({ method: "eth_chainId" });
    const address = accounts?.[0] as `0x${string}`;
    const balanceWei: string = await eth.request({ method: "eth_getBalance", params: [address, "latest"] });
    setWallet({ connected: true, address, chainId, balanceWei });
    eth.on?.("accountsChanged", (accs: string[]) => {
      setWallet((w) => ({ ...w, address: accs?.[0] as `0x${string}`, connected: !!accs?.[0] }));
    });
    eth.on?.("chainChanged", (cid: string) => {
      setWallet((w) => ({ ...w, chainId: cid }));
    });
  }, []);

  const signMessage = useCallback(async (message: string) => {
    const eth = (window as any).ethereum;
    if (!eth) throw new Error("Кошелек не подключен");
    if (!wallet.address) throw new Error("Неизвестен адрес кошелька");
    // EIP-191 personal_sign
    const sig: string = await eth.request({
      method: "personal_sign",
      params: [message, wallet.address],
    });
    return sig;
  }, [wallet.address]);

  return { wallet, connect, signMessage };
}

function useDAOData(params: {
  state?: ProposalState | "any";
  q?: string;
  from?: string;
  to?: string;
}) {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [proposals, setProposals] = useState<Proposal[]>([]);
  const [metrics, setMetrics] = useState<GovernanceMetrics | null>(null);
  const [series, setSeries] = useState<SeriesPoint[]>([]);
  const [votes, setVotes] = useState<VoteBreakdown[]>([]);
  const abortRef = useRef<AbortController | null>(null);

  const deb = useDebounced(params, 400);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;

    const qs = new URLSearchParams();
    if (deb.state && deb.state !== "any") qs.set("state", deb.state);
    if (deb.q) qs.set("q", deb.q);
    if (deb.from) qs.set("from", deb.from);
    if (deb.to) qs.set("to", deb.to);

    try {
      const [p, m, s, vb] = await Promise.all([
        fetch(`${API_BASE}/proposals?${qs.toString()}`, { signal: ac.signal }),
        fetch(`${API_BASE}/metrics?${qs.toString()}`, { signal: ac.signal }),
        fetch(`${API_BASE}/series?${qs.toString()}`, { signal: ac.signal }),
        fetch(`${API_BASE}/votes-breakdown?${qs.toString()}`, { signal: ac.signal }),
      ]);
      if (!p.ok || !m.ok || !s.ok || !vb.ok) {
        const detail = `proposals:${p.status} metrics:${m.status} series:${s.status} votes:${vb.status}`;
        throw new Error(`Backend error: ${detail}`);
      }
      const [pJson, mJson, sJson, vbJson] = await Promise.all([p.json(), m.json(), s.json(), vb.json()]);
      setProposals(pJson as Proposal[]);
      setMetrics(mJson as GovernanceMetrics);
      setSeries(sJson as SeriesPoint[]);
      setVotes(vbJson as VoteBreakdown[]);
    } catch (e: any) {
      if (e?.name !== "AbortError") setError(e?.message || "Unknown error");
    } finally {
      setLoading(false);
    }
  }, [deb]);

  useEffect(() => {
    load();
    return () => abortRef.current?.abort();
  }, [load]);

  return { loading, error, proposals, metrics, series, votes, reload: load };
}

function useDAOEvents(enabled: boolean) {
  const [connected, setConnected] = useState(false);
  const [lines, setLines] = useState<string[]>([]);
  useEffect(() => {
    if (!enabled || !WS_URL) return;
    const ws = new WebSocket(WS_URL);
    ws.onopen = () => setConnected(true);
    ws.onclose = () => setConnected(false);
    ws.onerror = () => setConnected(false);
    ws.onmessage = (m) => {
      if (typeof m.data === "string") {
        setLines((prev) => {
          const next = [...prev, m.data];
          if (next.length > LOG_LIMIT) next.splice(0, next.length - LOG_LIMIT);
          return next;
        });
      }
    };
    return () => ws.close();
  }, [enabled]);
  const clear = useCallback(() => setLines([]), []);
  return { connected, lines, clear };
}

// ---------- Error boundary ----------
class ErrorBoundary extends React.Component<
  { fallback: React.ReactNode; children: React.ReactNode },
  { hasError: boolean }
> {
  constructor(props: any) {
    super(props);
    this.state = { hasError: false };
  }
  static getDerivedStateFromError() {
    return { hasError: true };
  }
  componentDidCatch(error: any, info: any) {
    console.error("DAOGovernance crashed:", error, info);
  }
  render() {
    if (this.state.hasError) return this.props.fallback;
    return this.props.children;
  }
}
function ErrorBoundaryWrapper({ children }: { children: React.ReactNode }) {
  return (
    <ErrorBoundary
      fallback={
        <Card className="border-destructive/40">
          <CardHeader>
            <CardTitle>Ошибка загрузки панели</CardTitle>
            <CardDescription>Попробуйте обновить страницу или проверьте backend.</CardDescription>
          </CardHeader>
          <CardContent>
            <Button onClick={() => location.reload()} variant="secondary" className="gap-2">
              <RefreshCw className="h-4 w-4" />
              Обновить
            </Button>
          </CardContent>
        </Card>
      }
    >
      {children}
    </ErrorBoundary>
  );
}

// ---------- Main Page ----------
export default function DAOGovernance() {
  const { toast } = useToast();
  // Filters
  const [q, setQ] = usePersistedState<string>("dao.q", "");
  const [state, setState] = usePersistedState<ProposalState | "any">("dao.state", "any");
  const [from, setFrom] = usePersistedState<string>("dao.from", new Date(Date.now() - 1000 * 60 * 60 * 24 * 7).toISOString());
  const [to, setTo] = usePersistedState<string>("dao.to", new Date().toISOString());

  const { loading, error, proposals, metrics, series, votes, reload } = useDAOData({ q, state, from, to });

  // Wallet
  const { wallet, connect, signMessage } = useWallet();

  // Pagination
  const [page, setPage] = useState(0);
  const pages = Math.max(1, Math.ceil(proposals.length / PAGE_SIZE));
  useEffect(() => {
    if (page >= pages) setPage(0);
  }, [page, pages, proposals.length]);
  const pageSlice = useMemo(() => {
    const start = page * PAGE_SIZE;
    return proposals.slice(start, start + PAGE_SIZE);
  }, [proposals, page]);

  // Events
  const [live, setLive] = usePersistedState<boolean>("dao.live", true);
  const { connected, lines, clear } = useDAOEvents(live);

  // Create Proposal dialog
  const [openCreate, setOpenCreate] = useState(false);
  const [title, setTitle] = useState("");
  const [descr, setDescr] = useState("");
  const [actionsJson, setActionsJson] = useState(`{
  "targets": [],
  "values": [],
  "signatures": [],
  "calldatas": []
}`);
  const [votingDelay, setVotingDelay] = useState(0);
  const [votingPeriod, setVotingPeriod] = useState(43200);

  // Vote dialog
  const [openVote, setOpenVote] = useState(false);
  const [voteProposalId, setVoteProposalId] = useState<string>("");
  const [support, setSupport] = useState<0 | 1 | 2>(1);
  const [reason, setReason] = useState("");

  // Execute dialog
  const [execId, setExecId] = useState<string>("");
  const [openExec, setOpenExec] = useState(false);

  // Actions
  const doCreateProposal = useCallback(async () => {
    try {
      const payload: CreateProposalPayload = {
        title,
        description: descr,
        actionsJson,
        votingDelay,
        votingPeriod,
      };
      const r = await fetch(`${API_BASE}/proposals`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!r.ok) throw new Error(`Create failed: ${r.status}`);
      toast({ title: "Предложение создано", description: "Ожидайте начала голосования." });
      setOpenCreate(false);
      setTitle("");
      setDescr("");
      reload();
    } catch (e: any) {
      toast({ title: "Ошибка создания", description: e?.message || "Unknown", variant: "destructive" });
    }
  }, [title, descr, actionsJson, votingDelay, votingPeriod, reload, toast]);

  const openVoteDialog = useCallback((id: string) => {
    setVoteProposalId(id);
    setOpenVote(true);
  }, []);

  const doVote = useCallback(async () => {
    try {
      if (!wallet.connected || !wallet.address) throw new Error("Подключите кошелек");
      // Create a deterministic message for signing
      const nonceRes = await fetch(`${API_BASE}/vote-nonce?proposalId=${encodeURIComponent(voteProposalId)}&voter=${wallet.address}`);
      if (!nonceRes.ok) throw new Error("Не удалось получить nonce");
      const { nonce } = await nonceRes.json();
      const message = `DAO_VOTE\nproposalId:${voteProposalId}\nsupport:${support}\nreason:${reason || ""}\nnonce:${nonce}\nvoter:${wallet.address}`;
      const signature = await signMessage(message);
      const payload: CastVotePayload = {
        proposalId: voteProposalId,
        support,
        reason,
        voter: wallet.address,
        signature,
        nonce: String(nonce),
      };
      const r = await fetch(`${API_BASE}/vote`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!r.ok) throw new Error(`Vote failed: ${r.status}`);
      toast({ title: "Голос учтен", description: "Спасибо за участие в управлении." });
      setOpenVote(false);
      setReason("");
      reload();
    } catch (e: any) {
      toast({ title: "Ошибка голосования", description: e?.message || "Unknown", variant: "destructive" });
    }
  }, [wallet.connected, wallet.address, voteProposalId, support, reason, signMessage, reload, toast]);

  const openExecuteDialog = useCallback((id: string) => {
    setExecId(id);
    setOpenExec(true);
  }, []);
  const doExecute = useCallback(async () => {
    try {
      const r = await fetch(`${API_BASE}/execute`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ proposalId: execId }),
      });
      if (!r.ok) throw new Error(`Execute failed: ${r.status}`);
      toast({ title: "Исполнение инициировано", description: "Ожидайте подтверждения сети." });
      setOpenExec(false);
      reload();
    } catch (e: any) {
      toast({ title: "Ошибка исполнения", description: e?.message || "Unknown", variant: "destructive" });
    }
  }, [execId, reload, toast]);

  // Export
  const exportCSV = useCallback(() => {
    const headers = [
      "id",
      "title",
      "proposer",
      "state",
      "startTime",
      "endTime",
      "forVotes",
      "againstVotes",
      "abstainVotes",
      "quorum",
      "eta",
    ];
    const rows = proposals.map((p) =>
      [
        p.id,
        wrapCsv(p.title),
        p.proposer,
        p.state,
        p.startTime,
        p.endTime,
        p.forVotes,
        p.againstVotes,
        p.abstainVotes,
        p.quorum,
        p.eta ?? "",
      ].join(","),
    );
    const blob = new Blob([headers.join(",") + "\n" + rows.join("\n")], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.download = `dao_proposals_${Date.now()}.csv`;
    a.href = url;
    a.click();
    URL.revokeObjectURL(url);
  }, [proposals]);

  useEffect(() => {
    if (error) {
      // Announce
      toast({ title: "Ошибка загрузки", description: error, variant: "destructive" });
    }
  }, [error, toast]);

  const resetFilters = useCallback(() => {
    setQ("");
    setState("any");
    setFrom(new Date(Date.now() - 1000 * 60 * 60 * 24 * 7).toISOString());
    setTo(new Date().toISOString());
    setPage(0);
  }, [setQ, setState, setFrom, setTo]);

  // Render
  return (
    <ErrorBoundaryWrapper>
      <div className="flex flex-col gap-4 p-4 md:p-6" aria-label="DAO Governance Panel">
        <Header
          reload={reload}
          exportCSV={exportCSV}
          wallet={wallet}
          onConnect={connect}
        />

        <Filters
          q={q}
          setQ={setQ}
          state={state}
          setState={setState}
          from={from}
          to={to}
          setFrom={setFrom}
          setTo={setTo}
          reset={resetFilters}
        />

        <section className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4 md:gap-6">
          {metrics ? (
            <>
              <KpiCard title="Всего предложений" value={metrics.totalProposals} icon={Gavel} />
              <KpiCard title="Активные" value={metrics.activeProposals} icon={Activity} />
              <KpiCard title="Средний кворум" value={`${metrics.avgQuorumPct.toFixed(1)}%`} icon={Shield} />
              <KpiCard title="Явка избирателей" value={`${metrics.voterTurnoutPct.toFixed(1)}%`} icon={Users2} />
            </>
          ) : (
            <>
              <SkeletonCard title="Всего предложений" />
              <SkeletonCard title="Активные" />
              <SkeletonCard title="Средний кворум" />
              <SkeletonCard title="Явка" />
            </>
          )}
        </section>

        <section className="grid grid-cols-1 2xl:grid-cols-2 gap-4 md:gap-6">
          <Card>
            <CardHeader className="flex items-center justify-between flex-row">
              <div>
                <CardTitle className="flex items-center gap-2">
                  <LineChartIcon className="h-5 w-5" />
                  Активность DAO
                </CardTitle>
                <CardDescription>Динамика предложений и голосов</CardDescription>
              </div>
              <Badge variant="secondary">{series.length} точек</Badge>
            </CardHeader>
            <CardContent className="h-[320px]">
              {loading ? (
                <div className="h-full w-full animate-pulse rounded-xl bg-muted" />
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={series}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="t" tickFormatter={shortTime} />
                    <YAxis />
                    <Tooltip />
                    <Legend />
                    <Line type="monotone" dataKey="proposals" />
                    <Line type="monotone" dataKey="votes" />
                    <Line type="monotone" dataKey="turnoutPct" />
                  </LineChart>
                </ResponsiveContainer>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex items-center justify-between flex-row">
              <div>
                <CardTitle className="flex items-center gap-2">
                  <LineChartIcon className="h-5 w-5" />
                  Распределение голосов
                </CardTitle>
                <CardDescription>Суммы по дням</CardDescription>
              </div>
              <Badge variant="secondary">{votes.length} точек</Badge>
            </CardHeader>
            <CardContent className="h-[320px]">
              {loading ? (
                <div className="h-full w-full animate-pulse rounded-xl bg-muted" />
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={votes}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="day" />
                    <YAxis />
                    <Tooltip />
                    <Legend />
                    <Bar dataKey="for" />
                    <Bar dataKey="against" />
                    <Bar dataKey="abstain" />
                  </BarChart>
                </ResponsiveContainer>
              )}
            </CardContent>
          </Card>
        </section>

        <section className="grid grid-cols-1 xl:grid-cols-2 gap-4 md:gap-6">
          <ProposalsTable
            loading={loading}
            proposals={pageSlice}
            total={proposals.length}
            page={page}
            pages={pages}
            setPage={setPage}
            onVote={openVoteDialog}
            onExecute={openExecuteDialog}
          />

          <EventsCard
            enabled={live}
            setEnabled={setLive}
            connected={connected}
            lines={lines}
            clear={clear}
          />
        </section>

        <ActionsBar onOpenCreate={() => setOpenCreate(true)} />

        {/* Create Proposal */}
        <Dialog open={openCreate} onOpenChange={setOpenCreate}>
          <DialogContent className="sm:max-w-2xl">
            <DialogHeader>
              <DialogTitle>Создание предложения</DialogTitle>
            </DialogHeader>
            <div className="grid gap-4">
              <div className="grid gap-2">
                <Label>Заголовок</Label>
                <Input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Напр. Обновление параметров DAO" />
              </div>
              <div className="grid gap-2">
                <Label>Описание</Label>
                <Textarea value={descr} onChange={(e) => setDescr(e.target.value)} rows={4} placeholder="Краткая мотивация и детали" />
              </div>
              <div className="grid gap-2">
                <Label>Действия (JSON)</Label>
                <Textarea value={actionsJson} onChange={(e) => setActionsJson(e.target.value)} rows={6} />
              </div>
              <div className="grid md:grid-cols-2 gap-3">
                <div className="grid gap-2">
                  <Label>Voting Delay</Label>
                  <Input type="number" value={String(votingDelay)} onChange={(e) => setVotingDelay(Number(e.target.value || 0))} />
                </div>
                <div className="grid gap-2">
                  <Label>Voting Period</Label>
                  <Input type="number" value={String(votingPeriod)} onChange={(e) => setVotingPeriod(Number(e.target.value || 0))} />
                </div>
              </div>
            </div>
            <DialogFooter className="gap-2">
              <Button variant="secondary" onClick={() => setOpenCreate(false)}>Отмена</Button>
              <Button className="gap-2" onClick={doCreateProposal} disabled={!title.trim()}>
                <Plus className="h-4 w-4" />
                Создать
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* Vote */}
        <Dialog open={openVote} onOpenChange={setOpenVote}>
          <DialogContent className="sm:max-w-lg">
            <DialogHeader>
              <DialogTitle>Голосование по предложению #{voteProposalId}</DialogTitle>
            </DialogHeader>
            <div className="grid gap-4">
              <div className="grid gap-2">
                <Label>Поддержка</Label>
                <Select value={String(support)} onValueChange={(v) => setSupport(Number(v) as 0 | 1 | 2)}>
                  <SelectTrigger><SelectValue placeholder="Выберите" /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="1">За</SelectItem>
                    <SelectItem value="0">Против</SelectItem>
                    <SelectItem value="2">Воздержался</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-2">
                <Label>Причина (опционально)</Label>
                <Textarea value={reason} onChange={(e) => setReason(e.target.value)} rows={4} />
              </div>
              {!wallet.connected && (
                <div className="text-sm text-amber-700 bg-amber-50 border border-amber-200 p-2 rounded">
                  Для голосования подключите кошелек.
                </div>
              )}
            </div>
            <DialogFooter className="gap-2">
              <Button variant="secondary" onClick={() => setOpenVote(false)}>Отмена</Button>
              <Button className="gap-2" onClick={doVote} disabled={!wallet.connected}>
                <CheckCircle2 className="h-4 w-4" />
                Проголосовать
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* Execute */}
        <Dialog open={openExec} onOpenChange={setOpenExec}>
          <DialogContent className="sm:max-w-lg">
            <DialogHeader>
              <DialogTitle>Исполнение предложения #{execId}</DialogTitle>
            </DialogHeader>
            <div className="text-sm text-muted-foreground">
              Будет отправлен запрос к backend на исполнение действий предложения.
            </div>
            <DialogFooter className="gap-2">
              <Button variant="secondary" onClick={() => setOpenExec(false)}>Отмена</Button>
              <Button className="gap-2" onClick={doExecute}>
                <Gavel className="h-4 w-4" />
                Исполнить
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>
    </ErrorBoundaryWrapper>
  );
}

// ---------- Sub-components ----------
function Header({
  reload,
  exportCSV,
  wallet,
  onConnect,
}: {
  reload: () => void;
  exportCSV: () => void;
  wallet: Wallet;
  onConnect: () => Promise<void>;
}) {
  return (
    <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
      <motion.h1
        className="text-2xl md:text-3xl font-semibold tracking-tight"
        initial={{ opacity: 0, y: 4 }}
        animate={{ opacity: 1, y: 0 }}
      >
        DAO Governance
      </motion.h1>
      <div className="flex items-center gap-2">
        <Button variant="outline" className="gap-2" onClick={reload} aria-label="Обновить">
          <RefreshCw className="h-4 w-4" />
          Обновить
        </Button>
        <Button variant="outline" className="gap-2" onClick={exportCSV} aria-label="Экспорт CSV">
          <Download className="h-4 w-4" />
          Экспорт CSV
        </Button>
        {wallet.connected ? (
          <Badge variant="secondary" className="text-xs">
            {shortAddr(wallet.address!)} · chain {parseInt(wallet.chainId || "0x0", 16)}
          </Badge>
        ) : (
          <Button className="gap-2" onClick={onConnect}>
            <PlugZap className="h-4 w-4" />
            Подключить кошелек
          </Button>
        )}
      </div>
    </div>
  );
}

function Filters(props: {
  q: string;
  setQ: (v: string) => void;
  state: ProposalState | "any";
  setState: (v: ProposalState | "any") => void;
  from: string;
  to: string;
  setFrom: (v: string) => void;
  setTo: (v: string) => void;
  reset: () => void;
}) {
  const [fromLocal, setFromLocal] = useState(props.from);
  const [toLocal, setToLocal] = useState(props.to);
  useEffect(() => setFromLocal(props.from), [props.from]);
  useEffect(() => setToLocal(props.to), [props.to]);

  const applyDates = () => {
    props.setFrom(new Date(fromLocal).toISOString());
    props.setTo(new Date(toLocal).toISOString());
  };

  return (
    <Card>
      <CardHeader className="flex items-center justify-between flex-row">
        <div className="flex items-center gap-2">
          <Filter className="h-5 w-5" />
          <CardTitle>Фильтры</CardTitle>
        </div>
        <Button variant="secondary" onClick={props.reset}>Сбросить</Button>
      </CardHeader>
      <CardContent className="grid grid-cols-1 md:grid-cols-12 gap-3 md:gap-4">
        <div className="md:col-span-3">
          <Label htmlFor="from">От</Label>
          <Input
            id="from"
            type="datetime-local"
            value={toLocalDateTimeLocal(fromLocal)}
            onChange={(e) => setFromLocal(localToIso(e.target.value))}
          />
        </div>
        <div className="md:col-span-3">
          <Label htmlFor="to">До</Label>
          <Input
            id="to"
            type="datetime-local"
            value={toLocalDateTimeLocal(toLocal)}
            onChange={(e) => setToLocal(localToIso(e.target.value))}
          />
        </div>
        <div className="md:col-span-3">
          <Label>Состояние</Label>
          <Select value={props.state} onValueChange={(v) => props.setState(v as ProposalState | "any")}>
            <SelectTrigger><SelectValue placeholder="Любое" /></SelectTrigger>
            <SelectContent>
              <SelectItem value="any">Любое</SelectItem>
              <SelectItem value="Pending">Pending</SelectItem>
              <SelectItem value="Active">Active</SelectItem>
              <SelectItem value="Succeeded">Succeeded</SelectItem>
              <SelectItem value="Defeated">Defeated</SelectItem>
              <SelectItem value="Queued">Queued</SelectItem>
              <SelectItem value="Executed">Executed</SelectItem>
              <SelectItem value="Canceled">Canceled</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="md:col-span-3">
          <Label htmlFor="q">Поиск</Label>
          <Input id="q" value={props.q} onChange={(e) => props.setQ(e.target.value)} placeholder="ID, заголовок, адрес" />
        </div>
        <div className="md:col-span-12 flex justify-end gap-2">
          <Button variant="outline" onClick={applyDates}>Применить даты</Button>
        </div>
      </CardContent>
    </Card>
  );
}

function KpiCard({ title, value, icon: Icon }: { title: string; value: string | number; icon: React.ComponentType<any> }) {
  return (
    <Card>
      <CardHeader className="flex items-center justify-between flex-row">
        <CardTitle className="text-sm font-medium">{title}</CardTitle>
        <Icon className="h-5 w-5 text-muted-foreground" />
      </CardHeader>
      <CardContent>
        <div className="text-3xl font-bold">{value}</div>
      </CardContent>
    </Card>
  );
}
function SkeletonCard({ title }: { title: string }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        <CardDescription>Загрузка…</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="h-24 w-full animate-pulse rounded-xl bg-muted" />
      </CardContent>
    </Card>
  );
}

function ProposalsTable({
  loading,
  proposals,
  total,
  page,
  pages,
  setPage,
  onVote,
  onExecute,
}: {
  loading: boolean;
  proposals: Proposal[];
  total: number;
  page: number;
  pages: number;
  setPage: (p: number) => void;
  onVote: (id: string) => void;
  onExecute: (id: string) => void;
}) {
  return (
    <Card className="overflow-hidden">
      <CardHeader className="flex items-center justify-between flex-row">
        <div>
          <CardTitle className="flex items-center gap-2">
            <Gavel className="h-5 w-5" />
            Предложения
          </CardTitle>
          <CardDescription>Всего: {total}</CardDescription>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" disabled={page <= 0} onClick={() => setPage(Math.max(0, page - 1))}>
            Назад
          </Button>
          <span className="text-sm">Стр. {page + 1} / {pages}</span>
          <Button variant="outline" size="sm" disabled={page >= pages - 1} onClick={() => setPage(Math.min(pages - 1, page + 1))}>
            Вперед
          </Button>
        </div>
      </CardHeader>
      <CardContent className="p-0">
        <div role="table" className="w-full">
          <div className="grid grid-cols-12 px-4 py-2 text-xs font-medium text-muted-foreground" role="row">
            <div className="col-span-2">ID</div>
            <div className="col-span-3">Заголовок</div>
            <div className="col-span-2">Период</div>
            <div className="col-span-2">Статус</div>
            <div className="col-span-2">Голоса</div>
            <div className="col-span-1">Действия</div>
          </div>
          <Separator />
          <ScrollArea className="h-[360px]">
            {loading ? (
              <div className="p-4">
                <div className="h-10 animate-pulse rounded bg-muted mb-2" />
                <div className="h-10 animate-pulse rounded bg-muted mb-2" />
                <div className="h-10 animate-pulse rounded bg-muted" />
              </div>
            ) : proposals.length === 0 ? (
              <div className="p-6 text-sm text-muted-foreground">Нет данных для выбранных фильтров.</div>
            ) : (
              <ul role="rowgroup">
                {proposals.map((p) => {
                  const totalVotes = bigSum(p.forVotes, bigSum(p.againstVotes, p.abstainVotes));
                  const quorumPct = pctOf(p.forVotes, p.quorum);
                  return (
                    <li key={p.id} role="row" className="grid grid-cols-12 px-4 py-2 hover:bg-muted/50 transition-colors">
                      <div className="col-span-2 text-xs md:text-sm">{p.id}</div>
                      <div className="col-span-3 text-sm">{p.title}</div>
                      <div className="col-span-2 text-xs md:text-sm">
                        <div>{formatDate(new Date(p.startTime), "yyyy-MM-dd HH:mm")}</div>
                        <div className="text-muted-foreground">{formatDate(new Date(p.endTime), "yyyy-MM-dd HH:mm")}</div>
                      </div>
                      <div className="col-span-2">
                        <StateBadge state={p.state} />
                        <div className="text-xs text-muted-foreground mt-1">Кворум: {quorumPct.toFixed(1)}%</div>
                      </div>
                      <div className="col-span-2 text-xs md:text-sm">
                        <div>За: {fmtBig(p.forVotes)}</div>
                        <div>Против: {fmtBig(p.againstVotes)}</div>
                        <div>Воздерж.: {fmtBig(p.abstainVotes)}</div>
                        <div className="text-muted-foreground mt-1">Всего: {fmtBig(totalVotes)}</div>
                      </div>
                      <div className="col-span-1 flex items-center gap-2">
                        {p.state === "Active" && (
                          <Button size="sm" variant="outline" onClick={() => onVote(p.id)}>
                            Голос
                          </Button>
                        )}
                        {p.state === "Queued" && (
                          <Button size="sm" onClick={() => onExecute(p.id)}>
                            Исполнить
                          </Button>
                        )}
                      </div>
                    </li>
                  );
                })}
              </ul>
            )}
          </ScrollArea>
        </div>
      </CardContent>
    </Card>
  );
}

function StateBadge({ state }: { state: ProposalState }) {
  const tone =
    state === "Active"
      ? "bg-blue-100 text-blue-700"
      : state === "Succeeded" || state === "Executed"
      ? "bg-emerald-100 text-emerald-700"
      : state === "Defeated" || state === "Canceled"
      ? "bg-red-100 text-red-700"
      : state === "Queued"
      ? "bg-amber-100 text-amber-700"
      : "bg-gray-100 text-gray-700";
  return <span className={cn("px-2 py-1 rounded text-xs", tone)}>{state}</span>;
}

function EventsCard({
  enabled,
  setEnabled,
  connected,
  lines,
  clear,
}: {
  enabled: boolean;
  setEnabled: (v: boolean) => void;
  connected: boolean;
  lines: string[];
  clear: () => void;
}) {
  const endRef = useRef<HTMLDivElement | null>(null);
  useEffect(() => endRef.current?.scrollIntoView({ behavior: "smooth" }), [lines.length]);
  return (
    <Card>
      <CardHeader className="flex items-center justify-between flex-row">
        <div>
          <CardTitle className="flex items-center gap-2">
            <Clock className="h-5 w-5" />
            Live-события
          </CardTitle>
          <CardDescription>{enabled ? (connected ? "Подключено" : "Подключение…") : "Отключено"}</CardDescription>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <Label htmlFor="live">Live</Label>
            <Switch id="live" checked={enabled} onCheckedChange={setEnabled} />
          </div>
          <Button variant="outline" size="sm" onClick={clear}>Очистить</Button>
        </div>
      </CardHeader>
      <CardContent>
        <div className="h-[360px] w-full rounded-lg bg-black text-green-300 font-mono text-xs p-3 overflow-auto" role="log" aria-live="polite">
          {lines.length === 0 ? (
            <span className="text-neutral-500">Нет событий</span>
          ) : (
            lines.map((l, i) => <div key={i} className="whitespace-pre-wrap">{l}</div>)
          )}
          <div ref={endRef} />
        </div>
      </CardContent>
    </Card>
  );
}

function ActionsBar({ onOpenCreate }: { onOpenCreate: () => void }) {
  return (
    <Card>
      <CardHeader className="flex items-center justify-between flex-row">
        <CardTitle className="flex items-center gap-2">
          <Gavel className="h-5 w-5" />
          Управление
        </CardTitle>
        <CardDescription>Создание предложений и операции</CardDescription>
      </CardHeader>
      <CardContent className="flex items-center gap-3 flex-wrap">
        <Button className="gap-2" onClick={onOpenCreate}>
          <Plus className="h-4 w-4" />
          Создать предложение
        </Button>
      </CardContent>
    </Card>
  );
}

// ---------- Helpers ----------
function toLocalDateTimeLocal(iso: string) {
  try {
    const d = new Date(iso);
    const yy = d.getFullYear();
    const mm = String(d.getMonth() + 1).padStart(2, "0");
    const dd = String(d.getDate()).padStart(2, "0");
    const hh = String(d.getHours()).padStart(2, "0");
    const mi = String(d.getMinutes()).padStart(2, "0");
    return `${yy}-${mm}-${dd}T${hh}:${mi}`;
  } catch {
    return "";
  }
}
function localToIso(local: string) {
  try {
    const d = new Date(local);
    return d.toISOString();
  } catch {
    return new Date().toISOString();
  }
}
function shortAddr(addr: `0x${string}`) {
  return `${addr.slice(0, 6)}…${addr.slice(-4)}`;
}
function wrapCsv(s: string) {
  const needs = s.includes(",") || s.includes("\n") || s.includes('"');
  return needs ? `"${s.replace(/"/g, '""')}"` : s;
}
function bigSum(a: string, b: string) {
  // decimal strings
  try {
    const x = BigInt(a);
    const y = BigInt(b);
    return (x + y).toString();
  } catch {
    return "0";
  }
}
function fmtBig(s: string) {
  try {
    const x = BigInt(s);
    return x.toString();
  } catch {
    return s;
  }
}
function pctOf(part: string, total: string) {
  try {
    const p = Number(BigInt(part));
    const t = Number(BigInt(total));
    if (t === 0) return 0;
    return (p / t) * 100;
  } catch {
    return 0;
  }
}
