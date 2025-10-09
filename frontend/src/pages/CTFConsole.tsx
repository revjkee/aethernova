// frontend/src/pages/CTFConsole.tsx
import * as React from "react";
import { useEffect, useMemo, useRef, useState, useCallback } from "react";
import { z } from "zod";
import {
  Activity,
  AlertTriangle,
  Check,
  ChevronDown,
  ChevronRight,
  Clock,
  CloudOff,
  Cloud,
  Download,
  FileSearch,
  Filter,
  Flame,
  LayoutGrid,
  Link as LinkIcon,
  Loader2,
  Lock,
  LogOut,
  Search,
  Send,
  Shield,
  ShieldCheck,
  Skull,
  TerminalSquare,
  Trophy,
  Users,
  X,
} from "lucide-react";

// shadcn/ui
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogClose,
} from "@/components/ui/dialog";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/components/ui/use-toast";
import { Separator } from "@/components/ui/separator";
import { Progress } from "@/components/ui/progress";
import { cn } from "@/lib/utils";

// ------------------------------------------------------------
// Типы
// ------------------------------------------------------------
type Difficulty = "easy" | "medium" | "hard" | "insane";
type Category = "web" | "pwn" | "crypto" | "reversing" | "forensics" | "misc";
type Verdict = "accepted" | "rejected" | "rate_limited" | "duplicate" | "late";
type TeamRole = "owner" | "member";

interface Challenge {
  id: string;
  title: string;
  category: Category;
  difficulty: Difficulty;
  points: number;
  solved: boolean;
  firstBloodTeam?: string | null;
  tags?: string[];
  short?: string; // краткое описание
  attachments?: { name: string; url: string }[];
  updatedAt: string; // ISO
}

interface SubmitResult {
  verdict: Verdict;
  message: string;
  pointsAwarded?: number;
}

interface Submission {
  id: string;
  challengeId: string;
  challengeTitle: string;
  flagPrefix?: string | null;
  verdict: Verdict;
  createdAt: string; // ISO
  pointsDelta: number;
}

interface ScoreRow {
  team: string;
  score: number;
  lastSubmitAt: string; // ISO
  solves: number;
}

interface TeamMember {
  id: string;
  name: string;
  role: TeamRole;
}

interface ContestState {
  title: string;
  startedAt: string; // ISO
  endsAt: string; // ISO
  isRunning: boolean;
  totalChallenges: number;
  solvedCount: number;
  infraStatus: "ok" | "degraded" | "down";
}

interface WSLine {
  ts: string;
  level: "info" | "warn" | "error" | "debug";
  source: string;
  text: string;
}

// ------------------------------------------------------------
// Валидация форм
// ------------------------------------------------------------
const flagSchema = z.object({
  challengeId: z.string().min(1, "Челлендж обязателен"),
  flag: z.string().min(3, "Слишком короткий флаг").max(256, "Слишком длинный флаг")
    .regex(/[A-Za-z0-9{}_:\-]+/, "Допустимы символы A-Z a-z 0-9 { } _ - :"),
});

type FlagForm = z.infer<typeof flagSchema>;

const inviteSchema = z.object({
  email: z.string().email("Введите корректный email"),
});

type InviteForm = z.infer<typeof inviteSchema>;

// ------------------------------------------------------------
// API-обёртка (замените пути на реальные эндпоинты)
// ------------------------------------------------------------
async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    ...init,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(text || `HTTP ${res.status}`);
  }
  return res.json();
}

const CtfApi = {
  contest: () => api<ContestState>("/api/ctf/contest"),
  challenges: (params: Partial<{ q: string; category: Category | "all"; difficulty: Difficulty | "all"; solved: "all" | "only" | "unsolved"; sort: string }>) => {
    const sp = new URLSearchParams();
    if (params.q) sp.set("q", params.q);
    if (params.category && params.category !== "all") sp.set("category", params.category);
    if (params.difficulty && params.difficulty !== "all") sp.set("difficulty", params.difficulty);
    if (params.solved && params.solved !== "all") sp.set("solved", params.solved);
    if (params.sort) sp.set("sort", params.sort);
    return api<Challenge[]>(`/api/ctf/challenges?${sp.toString()}`);
  },
  submit: (payload: FlagForm) => api<SubmitResult>("/api/ctf/submit", { method: "POST", body: JSON.stringify(payload) }),
  submissions: (page: number, perPage: number) => api<{ items: Submission[]; total: number; page: number; perPage: number }>("/api/ctf/submissions?" + new URLSearchParams({ page: String(page), perPage: String(perPage) })),
  scoreboard: () => api<ScoreRow[]>("/api/ctf/scoreboard"),
  team: () => api<{ name: string; members: TeamMember[]; inviteLink: string }>("/api/ctf/team"),
  invite: (payload: InviteForm) => api("/api/ctf/team/invite", { method: "POST", body: JSON.stringify(payload) }),
  wsToken: () => api<{ token: string }>("/api/ctf/ws-token"),
  logsPoll: (cursor?: string) => api<{ lines: WSLine[]; nextCursor?: string }>("/api/ctf/logs?cursor=" + (cursor ?? "")),
};

// ------------------------------------------------------------
// Вспомогательные компоненты
// ------------------------------------------------------------
function KeyStat({ icon, title, value, desc, color = "neutral" }: { icon: React.ReactNode; title: string; value: React.ReactNode; desc?: string; color?: "neutral" | "good" | "warn" | "bad" }) {
  const map = {
    neutral: "bg-slate-50",
    good: "bg-emerald-50",
    warn: "bg-amber-50",
    bad: "bg-rose-50",
  };
  return (
    <Card className="shadow-sm">
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <CardTitle className="text-sm">{title}</CardTitle>
        <div className={cn("p-2 rounded-xl", map[color])}>{icon}</div>
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-semibold">{value}</div>
        {desc && <div className="text-xs text-muted-foreground mt-1">{desc}</div>}
      </CardContent>
    </Card>
  );
}

function Pill({ children, className }: { children: React.ReactNode; className?: string }) {
  return <span className={cn("text-xs px-2 py-1 rounded-full border", className)}>{children}</span>;
}

function DiffBadge({ d }: { d: Difficulty }) {
  const map: Record<Difficulty, string> = {
    easy: "bg-emerald-100 text-emerald-900",
    medium: "bg-amber-100 text-amber-900",
    hard: "bg-rose-100 text-rose-900",
    insane: "bg-violet-100 text-violet-900",
  };
  return <Badge className={cn("font-normal", map[d])}>{d}</Badge>;
}

function CatBadge({ c }: { c: Category }) {
  const map: Record<Category, string> = {
    web: "bg-sky-100 text-sky-900",
    pwn: "bg-indigo-100 text-indigo-900",
    crypto: "bg-cyan-100 text-cyan-900",
    reversing: "bg-fuchsia-100 text-fuchsia-900",
    forensics: "bg-lime-100 text-lime-900",
    misc: "bg-slate-100 text-slate-900",
  };
  return <Badge className={cn("font-normal", map[c])}>{c}</Badge>;
}

function LevelDot({ level }: { level: WSLine["level"] }) {
  const c = level === "info" ? "text-slate-300" : level === "warn" ? "text-amber-300" : level === "error" ? "text-rose-300" : "text-sky-300";
  const bgClass = level === "info" ? "bg-slate-300" : level === "warn" ? "bg-amber-300" : level === "error" ? "bg-rose-300" : level === "debug" ? "bg-sky-300" : "";
  return <span className={cn("inline-block w-2 h-2 rounded-full", c, bgClass)} />;
}

// ------------------------------------------------------------
// Главный компонент
// ------------------------------------------------------------
export default function CTFConsolePage() {
  const { toast } = useToast();

  // Contest
  const [contest, setContest] = useState<ContestState | null>(null);
  const [now, setNow] = useState<number>(Date.now());

  // Challenges
  const [q, setQ] = useState("");
  const [cat, setCat] = useState<Category | "all">("all");
  const [diff, setDiff] = useState<Difficulty | "all">("all");
  const [solvedFilter, setSolvedFilter] = useState<"all" | "only" | "unsolved">("all");
  const [sort, setSort] = useState("pointsDesc");
  const [chals, setChals] = useState<Challenge[]>([]);
  const [activeChallenge, setActiveChallenge] = useState<Challenge | null>(null);
  const [previewOpen, setPreviewOpen] = useState(false);

  // Submit
  const [flagForm, setFlagForm] = useState<FlagForm>({ challengeId: "", flag: "" });
  const [submitting, setSubmitting] = useState(false);

  // Submissions history
  const [subs, setSubs] = useState<Submission[]>([]);
  const [subsPage, setSubsPage] = useState(1);
  const [subsPerPage, setSubsPerPage] = useState(20);
  const [subsTotal, setSubsTotal] = useState(0);

  // Scoreboard
  const [board, setBoard] = useState<ScoreRow[]>([]);

  // Team
  const [team, setTeam] = useState<{ name: string; members: TeamMember[]; inviteLink: string } | null>(null);
  const [inviteForm, setInviteForm] = useState<InviteForm>({ email: "" });

  // Live console
  const [wsConnected, setWsConnected] = useState(false);
  const [wsEnabled, setWsEnabled] = useState(true);
  const [wsLines, setWsLines] = useState<WSLine[]>([]);
  const [pollCursor, setPollCursor] = useState<string | undefined>(undefined);
  const termRef = useRef<HTMLDivElement>(null);
  const wsRef = useRef<WebSocket | null>(null);

  // UI
  const [exporting, setExporting] = useState(false);

  // ----------------------------------------------------------
  // Effects: загрузка базовых данных
  // ----------------------------------------------------------
  useEffect(() => {
    let mounted = true;
    (async () => {
      try {
        const [c, b, t] = await Promise.all([CtfApi.contest(), CtfApi.scoreboard(), CtfApi.team()]);
        if (!mounted) return;
        setContest(c);
        setBoard(b);
        setTeam(t);
      } catch (e: any) {
        toast({ title: "Ошибка загрузки состояния CTF", description: e?.message ?? "Неизвестная ошибка" });
      }
    })();
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => {
      mounted = false;
      clearInterval(timer);
    };
  }, [toast]);

  useEffect(() => {
    let active = true;
    (async () => {
      try {
        const list = await CtfApi.challenges({ q, category: cat, difficulty: diff, solved: solvedFilter, sort });
        if (!active) return;
        setChals(list);
        // если активный челлендж исчез — сбросим
        if (activeChallenge && !list.find(c => c.id === activeChallenge.id)) {
          setActiveChallenge(null);
        }
      } catch (e: any) {
        toast({ title: "Не удалось получить список задач", description: e?.message ?? "Неизвестная ошибка" });
      }
    })();
    return () => { active = false; };
  }, [q, cat, diff, solvedFilter, sort]); // toast исключаем чтобы не триггерить

  useEffect(() => {
    let ok = true;
    (async () => {
      try {
        const res = await CtfApi.submissions(subsPage, subsPerPage);
        if (!ok) return;
        setSubs(res.items);
        setSubsTotal(res.total);
      } catch (e: any) {
        toast({ title: "Ошибка загрузки сабмитов", description: e?.message ?? "Неизвестная ошибка" });
      }
    })();
    return () => { ok = false; };
  }, [subsPage, subsPerPage, toast]);

  // ----------------------------------------------------------
  // Live console: WebSocket + fallback poll
  // ----------------------------------------------------------
  const scrollTerminalToBottom = useCallback(() => {
    if (termRef.current) {
      termRef.current.scrollTop = termRef.current.scrollHeight;
    }
  }, []);

  useEffect(() => {
    scrollTerminalToBottom();
  }, [wsLines, scrollTerminalToBottom]);

  useEffect(() => {
    let closed = false;

    const openWS = async () => {
      try {
        const { token } = await CtfApi.wsToken(); // backend выдаёт краткоживущий токен
        const proto = location.protocol === "https:" ? "wss" : "ws";
        const url = `${proto}://${location.host}/api/ctf/ws?token=${encodeURIComponent(token)}`;
        const ws = new WebSocket(url);
        wsRef.current = ws;

        ws.onopen = () => setWsConnected(true);
        ws.onclose = () => setWsConnected(false);
        ws.onerror = () => setWsConnected(false);
        ws.onmessage = (ev) => {
          try {
            const parsed: WSLine = JSON.parse(ev.data);
            setWsLines((prev) => {
              const next = [...prev, parsed];
              // ограничим буфер
              if (next.length > 1000) next.shift();
              return next;
            });
          } catch {
            // игнор
          }
        };
      } catch {
        setWsConnected(false);
      }
    };

    if (wsEnabled) {
      openWS();
    }

    const pollInterval = setInterval(async () => {
      if (wsEnabled && wsConnected) return; // WS жив — poll не нужен
      try {
        const res = await CtfApi.logsPoll(pollCursor);
        if (res.lines?.length) {
          setWsLines((prev) => {
            const next = [...prev, ...res.lines];
            if (next.length > 1000) next.splice(0, next.length - 1000);
            return next;
          });
        }
        setPollCursor(res.nextCursor);
      } catch {
        // молча
      }
    }, 4000);

    return () => {
      closed = true;
      if (wsRef.current) {
        try { wsRef.current.close(); } catch {}
      }
      clearInterval(pollInterval);
    };
  }, [wsEnabled, wsConnected, pollCursor]);

  // ----------------------------------------------------------
  // Таймер
  // ----------------------------------------------------------
  const remaining = useMemo(() => {
    if (!contest) return { total: 0, hhmmss: "—" };
    const end = new Date(contest.endsAt).getTime();
    const delta = Math.max(0, end - now);
    const s = Math.floor(delta / 1000);
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = s % 60;
    const pad = (n: number) => String(n).padStart(2, "0");
    return { total: delta, hhmmss: `${pad(h)}:${pad(m)}:${pad(sec)}` };
  }, [contest, now]);

  // ----------------------------------------------------------
  // Сабмит флага
  // ----------------------------------------------------------
  const onSubmitFlag = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    try {
      const res = await CtfApi.submit(flagForm);
      toast({ title: verdictTitle(res.verdict), description: res.message });
      if (res.verdict === "accepted") {
        // обновим связанные состояния
        try {
          const [list, score, subsRes] = await Promise.all([
            CtfApi.challenges({ q, category: cat, difficulty: diff, solved: solvedFilter, sort }),
            CtfApi.scoreboard(),
            CtfApi.submissions(subsPage, subsPerPage),
          ]);
          setChals(list);
          setBoard(score);
          setSubs(subsRes.items);
          setSubsTotal(subsRes.total);
        } catch {}
        setFlagForm({ challengeId: flagForm.challengeId, flag: "" });
      }
    } catch (e: any) {
      toast({ title: "Ошибка отправки флага", description: e?.message ?? "Неизвестная ошибка" });
    } finally {
      setSubmitting(false);
    }
  };

  // ----------------------------------------------------------
  // Экспорт сабмитов (CSV)
  // ----------------------------------------------------------
  const exportSubs = async () => {
    setExporting(true);
    try {
      // простая генерация CSV на клиенте
      const header = ["id", "challengeId", "challengeTitle", "verdict", "createdAt", "pointsDelta"];
      const rows = subs.map(s => [s.id, s.challengeId, s.challengeTitle, s.verdict, s.createdAt, String(s.pointsDelta)]);
      const csv = [header, ...rows].map(r => r.map(escapeCsv).join(",")).join("\n");
      const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `submissions_${new Date().toISOString().replace(/[:.]/g, "-")}.csv`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } finally {
      setExporting(false);
    }
  };

  // ----------------------------------------------------------
  // Рендер
  // ----------------------------------------------------------
  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex items-start md:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <TerminalSquare className="h-6 w-6" />
          <div>
            <h1 className="text-xl font-semibold">{contest?.title ?? "CTF Console"}</h1>
            <p className="text-sm text-muted-foreground">Управление задачами, флагами, командой и живой консолью</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <Badge variant="outline" className={cn("gap-1", contest?.isRunning ? "border-emerald-300 text-emerald-800" : "border-slate-300 text-slate-800")}>
            {contest?.isRunning ? <Activity className="h-3.5 w-3.5" /> : <Lock className="h-3.5 w-3.5" />}
            {contest?.isRunning ? "В процессе" : "Закрыто"}
          </Badge>
          <Badge variant="outline" className={cn("gap-1",
            contest?.infraStatus === "ok" ? "border-emerald-300 text-emerald-800" : "",
            contest?.infraStatus === "degraded" ? "border-amber-300 text-amber-800" : "",
            contest?.infraStatus === "down" ? "border-rose-300 text-rose-800" : "")}>
            {contest?.infraStatus === "ok" ? <Cloud className="h-3.5 w-3.5" /> :
              contest?.infraStatus === "degraded" ? <AlertTriangle className="h-3.5 w-3.5" /> :
                <CloudOff className="h-3.5 w-3.5" />}
            Инфра: {contest?.infraStatus ?? "—"}
          </Badge>
          <Badge variant="outline" className="gap-1">
            <Clock className="h-3.5 w-3.5" />
            До конца: {remaining.hhmmss}
          </Badge>
        </div>
      </div>

      {/* Stats */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <KeyStat icon={<LayoutGrid className="h-4 w-4" />} title="Всего задач" value={contest?.totalChallenges ?? "—"} desc="Активных в ротации" />
        <KeyStat icon={<ShieldCheck className="h-4 w-4" />} title="Решено" value={contest?.solvedCount ?? "—"} desc="Вашей командой" color="good" />
        <KeyStat icon={<Trophy className="h-4 w-4" />} title="Позиция" value={positionInBoard(board, team?.name)} desc="Текущее место" />
        <KeyStat icon={<Flame className="h-4 w-4" />} title="Темп сабмитов" value={`${subs.length}/стр`} desc="На текущей странице" />
      </div>

      <Tabs defaultValue="challenges" className="w-full">
        <TabsList className="grid w-full grid-cols-5">
          <TabsTrigger value="challenges">Задачи</TabsTrigger>
          <TabsTrigger value="submit">Сабмит</TabsTrigger>
          <TabsTrigger value="submissions">История</TabsTrigger>
          <TabsTrigger value="team">Команда</TabsTrigger>
          <TabsTrigger value="console">Консоль</TabsTrigger>
        </TabsList>

        {/* Challenges */}
        <TabsContent value="challenges" className="mt-4 space-y-4">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base">Задачи</CardTitle>
              <CardDescription>Фильтры, поиск, предпросмотр и вложения</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex flex-col md:flex-row gap-3">
                <div className="relative md:w-80">
                  <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
                  <Input placeholder="Поиск по названию, тегам" className="pl-8" value={q} onChange={(e) => setQ(e.target.value)} />
                </div>
                <Select value={cat} onValueChange={(v) => setCat(v as any)}>
                  <SelectTrigger className="w-44"><SelectValue placeholder="Категория" /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">Все</SelectItem>
                    <SelectItem value="web">web</SelectItem>
                    <SelectItem value="pwn">pwn</SelectItem>
                    <SelectItem value="crypto">crypto</SelectItem>
                    <SelectItem value="reversing">reversing</SelectItem>
                    <SelectItem value="forensics">forensics</SelectItem>
                    <SelectItem value="misc">misc</SelectItem>
                  </SelectContent>
                </Select>
                <Select value={diff} onValueChange={(v) => setDiff(v as any)}>
                  <SelectTrigger className="w-44"><SelectValue placeholder="Сложность" /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">Все</SelectItem>
                    <SelectItem value="easy">easy</SelectItem>
                    <SelectItem value="medium">medium</SelectItem>
                    <SelectItem value="hard">hard</SelectItem>
                    <SelectItem value="insane">insane</SelectItem>
                  </SelectContent>
                </Select>
                <Select value={solvedFilter} onValueChange={(v) => setSolvedFilter(v as any)}>
                  <SelectTrigger className="w-44"><SelectValue placeholder="Решённость" /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">Все</SelectItem>
                    <SelectItem value="only">Только решённые</SelectItem>
                    <SelectItem value="unsolved">Только нерешённые</SelectItem>
                  </SelectContent>
                </Select>
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button variant="outline"><Filter className="mr-2 h-4 w-4" /> Сортировка</Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="start">
                    <DropdownMenuLabel>Сортировать по</DropdownMenuLabel>
                    <DropdownMenuItem onClick={() => setSort("pointsDesc")}>Очки по убыванию</DropdownMenuItem>
                    <DropdownMenuItem onClick={() => setSort("updatedDesc")}>Обновлено недавно</DropdownMenuItem>
                    <DropdownMenuItem onClick={() => setSort("categoryAsc")}>Категория A→Z</DropdownMenuItem>
                    <DropdownMenuItem onClick={() => setSort("titleAsc")}>Название A→Z</DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
              </div>

              <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
                {chals.map(c => (
                  <Card key={c.id} className={cn("transition", c.solved ? "ring-1 ring-emerald-200" : "")}>
                    <CardHeader className="pb-2">
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <CardTitle className="text-base">{c.title}</CardTitle>
                          <CardDescription className="flex items-center gap-2">
                            <CatBadge c={c.category} />
                            <DiffBadge d={c.difficulty} />
                            <Pill className="ml-1">+{c.points} pts</Pill>
                            {c.firstBloodTeam && <Pill className="ml-1 border-rose-200 text-rose-800">first blood: {c.firstBloodTeam}</Pill>}
                          </CardDescription>
                        </div>
                        {c.solved ? <Badge className="bg-emerald-100 text-emerald-900">Solved</Badge> : <Badge variant="outline">Open</Badge>}
                      </div>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      <p className="text-sm text-muted-foreground line-clamp-3">{c.short ?? "Описание недоступно"}</p>
                      {c.tags && c.tags.length > 0 && (
                        <div className="flex gap-1 flex-wrap">
                          {c.tags.map(t => <Pill key={t}>{t}</Pill>)}
                        </div>
                      )}
                      {c.attachments && c.attachments.length > 0 && (
                        <div className="flex flex-wrap gap-2">
                          {c.attachments.map(a => (
                            <a key={a.url} href={a.url} className="text-sm inline-flex items-center gap-1 underline decoration-dotted">
                              <Download className="h-3.5 w-3.5" /> {a.name}
                            </a>
                          ))}
                        </div>
                      )}
                    </CardContent>
                    <CardFooter className="justify-between">
                      <Button variant="outline" onClick={() => { setActiveChallenge(c); setPreviewOpen(true); setFlagForm({ ...flagForm, challengeId: c.id }); }}>
                        <FileSearch className="mr-2 h-4 w-4" /> Предпросмотр
                      </Button>
                      <Button onClick={() => { setFlagForm({ ...flagForm, challengeId: c.id }); window.scrollTo({ top: 0, behavior: "smooth" }); }}>
                        <Send className="mr-2 h-4 w-4" /> К сабмиту
                      </Button>
                    </CardFooter>
                  </Card>
                ))}
              </div>

              {chals.length === 0 && (
                <div className="text-sm text-muted-foreground py-6 text-center">Задачи не найдены под текущие фильтры</div>
              )}
            </CardContent>
          </Card>

          <Sheet open={previewOpen} onOpenChange={setPreviewOpen}>
            <SheetContent side="right" className="w-full sm:max-w-xl">
              <SheetHeader>
                <SheetTitle className="flex items-center gap-2">
                  {activeChallenge?.title ?? "—"}
                  {activeChallenge && <Pill>+{activeChallenge.points}</Pill>}
                </SheetTitle>
                <SheetDescription className="flex items-center gap-2">
                  {activeChallenge && <>
                    <CatBadge c={activeChallenge.category} />
                    <DiffBadge d={activeChallenge.difficulty} />
                  </>}
                </SheetDescription>
              </SheetHeader>
              <div className="py-4 space-y-4">
                <div className="text-sm whitespace-pre-wrap">{activeChallenge?.short ?? "Описание недоступно"}</div>
                {activeChallenge?.attachments && activeChallenge.attachments.length > 0 && (
                  <div>
                    <Label>Вложения</Label>
                    <div className="mt-2 flex flex-col gap-2">
                      {activeChallenge.attachments.map(a => (
                        <a key={a.url} href={a.url} className="text-sm inline-flex items-center gap-1 underline decoration-dotted">
                          <Download className="h-3.5 w-3.5" /> {a.name}
                        </a>
                      ))}
                    </div>
                  </div>
                )}
                <Separator />
                <div className="text-xs text-muted-foreground">Обновлено: {activeChallenge ? new Date(activeChallenge.updatedAt).toLocaleString() : "—"}</div>
              </div>
            </SheetContent>
          </Sheet>
        </TabsContent>

        {/* Submit */}
        <TabsContent value="submit" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Сабмит флага</CardTitle>
              <CardDescription>Валидация и устойчивость к ошибкам</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <form className="space-y-4" onSubmit={onSubmitFlag}>
                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="space-y-2">
                    <Label>Челлендж</Label>
                    <Select value={flagForm.challengeId} onValueChange={(v) => setFlagForm({ ...flagForm, challengeId: v })}>
                      <SelectTrigger><SelectValue placeholder="Выберите задачу" /></SelectTrigger>
                      <SelectContent>
                        {chals.map(c => <SelectItem key={c.id} value={c.id}>{c.title} (+{c.points})</SelectItem>)}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2">
                    <Label>Флаг</Label>
                    <Input placeholder="FLAG{...}" value={flagForm.flag} onChange={(e) => setFlagForm({ ...flagForm, flag: e.target.value })} />
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Button type="submit" disabled={submitting}>
                    {submitting ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Send className="mr-2 h-4 w-4" />}
                    Отправить
                  </Button>
                  <Badge variant="outline" className="gap-1">
                    <Shield className="h-3.5 w-3.5" /> Антиспам: серверный rate-limit
                  </Badge>
                </div>
              </form>
            </CardContent>
            <CardFooter className="justify-between text-sm text-muted-foreground">
              <div className="flex items-center gap-2">
                <Skull className="h-4 w-4" /> Неверные флаги логируются без деталей
              </div>
              <div className="flex items-center gap-2">
                <LinkIcon className="h-4 w-4" /> Подсказок нет
              </div>
            </CardFooter>
          </Card>
        </TabsContent>

        {/* Submissions */}
        <TabsContent value="submissions" className="mt-4 space-y-3">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base">История сабмитов</CardTitle>
              <CardDescription>Пагинация, экспорт CSV</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex justify-between">
                <div className="text-sm text-muted-foreground">
                  Показано {(subs.length > 0) ? ((subsPage - 1) * subsPerPage + 1) : 0}–{(subsPage - 1) * subsPerPage + subs.length} из {subsTotal}
                </div>
                <div className="flex items-center gap-2">
                  <Select value={String(subsPerPage)} onValueChange={(v) => { setSubsPage(1); setSubsPerPage(Number(v)); }}>
                    <SelectTrigger className="w-28"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {[10, 20, 50, 100].map(n => <SelectItem key={n} value={String(n)}>{n} / стр</SelectItem>)}
                    </SelectContent>
                  </Select>
                  <Button variant="outline" size="sm" onClick={() => setSubsPage(p => Math.max(1, p - 1))} disabled={subsPage <= 1}>Назад</Button>
                  <div className="text-sm w-16 text-center">стр. {subsPage}/{Math.max(1, Math.ceil(subsTotal / subsPerPage))}</div>
                  <Button variant="outline" size="sm" onClick={() => setSubsPage(p => Math.min(Math.ceil(subsTotal / subsPerPage), p + 1))} disabled={subsPage >= Math.max(1, Math.ceil(subsTotal / subsPerPage))}>Далее</Button>
                  <Button variant="outline" size="sm" onClick={exportSubs} disabled={exporting}>
                    {exporting ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Download className="mr-2 h-4 w-4" />} Экспорт CSV
                  </Button>
                </div>
              </div>
              <div className="rounded-md border">
                <Table>
                  <TableHeader>
                    <TableRow className="hover:bg-transparent">
                      <TableHead className="w-36">Время</TableHead>
                      <TableHead className="w-48">Задача</TableHead>
                      <TableHead className="w-36">Вердикт</TableHead>
                      <TableHead className="w-24 text-right">Очки</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {subs.map(s => (
                      <TableRow key={s.id}>
                        <TableCell className="text-sm">{new Date(s.createdAt).toLocaleString()}</TableCell>
                        <TableCell className="text-sm">{s.challengeTitle}</TableCell>
                        <TableCell className="text-sm">
                          <VerdictBadge v={s.verdict} />
                        </TableCell>
                        <TableCell className="text-right font-mono text-xs">{s.pointsDelta >= 0 ? `+${s.pointsDelta}` : s.pointsDelta}</TableCell>
                      </TableRow>
                    ))}
                    {subs.length === 0 && (
                      <TableRow>
                        <TableCell colSpan={4} className="text-center py-10 text-sm text-muted-foreground">Нет данных</TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Team */}
        <TabsContent value="team" className="mt-4">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base">Команда</CardTitle>
              <CardDescription>Состав и инвайты</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
                <div className="text-sm">
                  <div className="font-medium">{team?.name ?? "—"}</div>
                  <div className="text-muted-foreground">Участников: {team?.members.length ?? 0}</div>
                </div>
                <div className="flex items-center gap-2">
                  <Input readOnly value={team?.inviteLink ?? ""} className="md:w-96" />
                  <Button variant="outline" onClick={() => { if (team?.inviteLink) { navigator.clipboard.writeText(team.inviteLink); toast({ title: "Скопировано" }); } }}>
                    <LinkIcon className="mr-2 h-4 w-4" /> Копировать
                  </Button>
                </div>
              </div>

              <div className="rounded-md border">
                <Table>
                  <TableHeader>
                    <TableRow className="hover:bg-transparent">
                      <TableHead className="w-48">Имя</TableHead>
                      <TableHead className="w-24">Роль</TableHead>
                      <TableHead className="w-24 text-right">Действия</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {team?.members.map(m => (
                      <TableRow key={m.id}>
                        <TableCell className="text-sm">{m.name}</TableCell>
                        <TableCell className="text-sm">
                          <Badge variant="outline">{m.role}</Badge>
                        </TableCell>
                        <TableCell className="text-right">
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button variant="ghost" className="h-8 w-8 p-0">
                                <span className="sr-only">Открыть меню</span>
                                <ChevronDown className="h-4 w-4" />
                              </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end">
                              <DropdownMenuItem disabled>Передать владельца</DropdownMenuItem>
                              <DropdownMenuItem className="text-rose-700" disabled>Исключить</DropdownMenuItem>
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </TableCell>
                      </TableRow>
                    ))}
                    {(team?.members?.length ?? 0) === 0 && (
                      <TableRow>
                        <TableCell colSpan={3} className="text-center py-10 text-sm text-muted-foreground">Пусто</TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </div>

              <Separator />
              <form className="grid gap-3 sm:grid-cols-2" onSubmit={async (e) => { 
                e.preventDefault(); 
                try {
                  await CtfApi.invite(inviteForm);
                  toast({ title: "Инвайт отправлен", description: inviteForm.email });
                  setInviteForm({ email: "" });
                } catch (e: any) {
                  toast({ title: "Ошибка инвайта", description: e?.message ?? "Неизвестная ошибка" });
                }
              }}>
                <div className="space-y-2">
                  <Label>Email инвайта</Label>
                  <Input placeholder="user@example.com" value={inviteForm.email} onChange={(e) => setInviteForm({ email: e.target.value })} />
                </div>
                <div className="self-end">
                  <Button type="submit"><Send className="mr-2 h-4 w-4" /> Отправить приглашение</Button>
                </div>
              </form>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Console */}
        <TabsContent value="console" className="mt-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-base">Живая консоль</CardTitle>
              <CardDescription>WebSocket {wsConnected ? "подключен" : "отключен"}, при отключении работает резервный poll</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Switch checked={wsEnabled} onCheckedChange={setWsEnabled} />
                  <span className="text-sm">Включить WebSocket</span>
                </div>
                <div className="flex items-center gap-2 text-sm text-muted-foreground">
                  <span className={cn("inline-flex items-center gap-1", wsConnected ? "text-emerald-700" : "text-rose-700")}>
                    {wsConnected ? <Cloud className="h-4 w-4" /> : <CloudOff className="h-4 w-4" />} {wsConnected ? "Online" : "Offline"}
                  </span>
                </div>
              </div>
              <div ref={termRef} className="rounded-md border bg-black text-white text-xs font-mono p-3 h-80 overflow-auto">
                {wsLines.length === 0 ? (
                  <div className="text-slate-400">Лог пуст</div>
                ) : (
                  wsLines.map((l, i) => (
                    <div key={i} className="whitespace-pre-wrap">
                      <span className="text-slate-400">{new Date(l.ts).toLocaleTimeString()}</span>{" "}
                      <span>[</span><span className={cn(l.level === "error" ? "text-rose-300" : "", l.level === "warn" ? "text-amber-300" : "", l.level === "debug" ? "text-sky-300" : "")}>{l.level.toUpperCase()}</span><span>]</span>{" "}
                      <span className="text-slate-300">{l.source}</span>{" "}
                      <span className="text-white">{l.text}</span>
                    </div>
                  ))
                )}
              </div>
            </CardContent>
            <CardFooter className="justify-between text-sm text-muted-foreground">
              <div className="flex items-center gap-2"><TerminalSquare className="h-4 w-4" /> Буфер: {wsLines.length}</div>
              <div className="flex items-center gap-2"><Activity className="h-4 w-4" /> Автопрокрутка: включена</div>
            </CardFooter>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Scoreboard */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-base">Табло очков</CardTitle>
          <CardDescription>Первые 10 команд</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="w-16">#</TableHead>
                  <TableHead>Команда</TableHead>
                  <TableHead className="w-36">Очки</TableHead>
                  <TableHead className="w-48">Последний сабмит</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {board.slice(0, 10).map((r, i) => (
                  <TableRow key={r.team}>
                    <TableCell className="font-semibold">{i + 1}</TableCell>
                    <TableCell className={cn("text-sm", team?.name === r.team ? "font-semibold" : "")}>{r.team}</TableCell>
                    <TableCell className="text-sm">{r.score}</TableCell>
                    <TableCell className="text-sm">{new Date(r.lastSubmitAt).toLocaleString()}</TableCell>
                  </TableRow>
                ))}
                {board.length === 0 && (
                  <TableRow><TableCell colSpan={4} className="text-center py-10 text-sm text-muted-foreground">Нет данных</TableCell></TableRow>
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// ------------------------------------------------------------
// Мелкие компоненты/утилиты
// ------------------------------------------------------------
function VerdictBadge({ v }: { v: Verdict }) {
  const map: Record<Verdict, { text: string; cls: string; icon: React.ReactNode }> = {
    accepted: { text: "ACCEPTED", cls: "bg-emerald-100 text-emerald-900", icon: <Check className="h-3.5 w-3.5" /> },
    rejected: { text: "REJECTED", cls: "bg-rose-100 text-rose-900", icon: <X className="h-3.5 w-3.5" /> },
    rate_limited: { text: "RATE LIMITED", cls: "bg-amber-100 text-amber-900", icon: <AlertTriangle className="h-3.5 w-3.5" /> },
    duplicate: { text: "DUPLICATE", cls: "bg-slate-100 text-slate-900", icon: <ChevronRight className="h-3.5 w-3.5" /> },
    late: { text: "LATE", cls: "bg-slate-200 text-slate-800", icon: <Clock className="h-3.5 w-3.5" /> },
  };
  const m = map[v];
  return <Badge className={cn("gap-1 font-normal", m.cls)}>{m.icon}{m.text}</Badge>;
}

function verdictTitle(v: Verdict) {
  switch (v) {
    case "accepted": return "Флаг принят";
    case "duplicate": return "Уже принято";
    case "rate_limited": return "Слишком часто";
    case "late": return "Просрочено";
    case "rejected": default: return "Флаг отклонён";
  }
}

function positionInBoard(rows: ScoreRow[], teamName?: string) {
  if (!teamName) return "—";
  const idx = rows.findIndex(r => r.team === teamName);
  return idx >= 0 ? idx + 1 : "—";
}

function escapeCsv(s: string) {
  if (s == null) return "";
  if (/[",\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}
