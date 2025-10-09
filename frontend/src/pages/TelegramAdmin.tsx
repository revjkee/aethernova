// frontend/src/pages/TelegramAdmin.tsx
import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { FC } from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import { Progress } from "@/components/ui/progress";
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import {
  AlertCircle,
  AtSign,
  Ban,
  CheckCircle2,
  ChevronDown,
  Clipboard,
  Download,
  Edit3,
  ExternalLink,
  FileUp,
  Filter,
  History,
  ListChecks,
  Loader2,
  Lock,
  Mail,
  Megaphone,
  PlayCircle,
  RefreshCcw,
  Save,
  Search,
  Send,
  Shield,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Trash2,
  Upload,
  UserCog,
  Users,
  View,
  EyeOff,
} from "lucide-react";
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip as RechartsTooltip,
  Legend,
} from "recharts";

// ==============================
// Types
// ==============================
type Mode = "webhook" | "polling";
type LogLevel = "info" | "warn" | "error" | "debug";
type Role = "admin" | "moderator" | "user";
type ParseMode = "plain" | "markdown" | "html";
type SegRole = "any" | Role;

interface TelegramBotConfig {
  enabled: boolean;
  mode: Mode;
  botUsername?: string;
  botId?: number;
  tokenMasked: string; // masked in UI
  tokenPlain?: string; // only local state while editing
  webhookUrl?: string;
  allowedUpdates: string[];
  requestTimeoutSec: number;
  rateLimitPerMin: number;
}

interface TelegramUser {
  id: number;
  username?: string;
  firstName?: string;
  lastName?: string;
  role: Role;
  banned: boolean;
  lastSeenTs: number;
  messagesCount: number;
}

interface BroadcastJob {
  id: string;
  title: string;
  createdAt: number;
  startedAt?: number;
  finishedAt?: number;
  total: number;
  processed: number;
  success: number;
  failed: number;
  dryRun: boolean;
  status: "queued" | "running" | "done" | "failed" | "canceled";
}

interface TestSendPayload {
  chatId: string;
  text: string;
  parseMode: ParseMode;
  linkPreview: boolean;
}

interface BroadcastPayload {
  title: string;
  message: string;
  parseMode: ParseMode;
  dryRun: boolean;
  includeImageUrl?: string;
  minMessages?: number;
  role: SegRole;
}

interface LogEntry {
  id: string;
  ts: number;
  level: LogLevel;
  message: string;
  meta?: Record<string, any>;
}

interface FetchPage<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

// ==============================
// Utilities
// ==============================
const fmtDate = (ts: number) => {
  const d = new Date(ts);
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  const h = String(d.getHours()).padStart(2, "0");
  const mi = String(d.getMinutes()).padStart(2, "0");
  const s = String(d.getSeconds()).padStart(2, "0");
  return `${y}-${m}-${day} ${h}:${mi}:${s}`;
};

function debounce<T extends (...args: any[]) => void>(fn: T, ms = 300) {
  let h: number | undefined;
  return (...args: Parameters<T>) => {
    if (h) window.clearTimeout(h);
    h = window.setTimeout(() => fn(...args), ms);
  };
}

function downloadCsv(filename: string, rows: Record<string, any>[]) {
  if (!rows.length) return;
  const headers = Object.keys(rows[0]);
  const esc = (v: any) =>
    `"${String(v ?? "").replace(/"/g, '""').replace(/\n/g, " ")}"`;
  const csv =
    headers.join(",") +
    "\n" +
    rows.map((r) => headers.map((h) => esc(r[h])).join(",")).join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

const maskToken = (t?: string) =>
  t ? `${t.slice(0, 9)}••••••••••••••••••••••••••••${t.slice(-4)}` : "";

// ==============================
// Mock API (replace with real backend calls)
// ==============================
const MOCK_ALLOWED = ["message", "edited_message", "callback_query", "chat_member", "my_chat_member"];

function randomInt(min: number, max: number) {
  return Math.floor(min + Math.random() * (max - min + 1));
}

function mockConfig(): Promise<TelegramBotConfig> {
  return new Promise((resolve) =>
    setTimeout(
      () =>
        resolve({
          enabled: true,
          mode: "webhook",
          botUsername: "my_bot",
          botId: 123456789,
          tokenMasked: maskToken("123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"),
          webhookUrl: "https://example.com/api/telegram/webhook",
          allowedUpdates: [...MOCK_ALLOWED],
          requestTimeoutSec: 20,
          rateLimitPerMin: 120,
        }),
      300
    )
  );
}

function mockSaveConfig(cfg: TelegramBotConfig): Promise<TelegramBotConfig> {
  return new Promise((resolve, reject) =>
    setTimeout(() => {
      if (!cfg.mode) return reject(new Error("Неверный режим"));
      resolve({
        ...cfg,
        tokenMasked: cfg.tokenPlain ? maskToken(cfg.tokenPlain) : cfg.tokenMasked,
        tokenPlain: undefined,
      });
    }, 400)
  );
}

function mockUsers(limit: number, offset: number, q: string, role: SegRole): Promise<FetchPage<TelegramUser>> {
  return new Promise((resolve) =>
    setTimeout(() => {
      const total = 1387;
      const users: TelegramUser[] = Array.from({ length: Math.min(limit, Math.max(0, total - offset)) }, (_, i) => {
        const id = offset + i + 1;
        const r: Role = ["admin", "moderator", "user"][id % 3] as Role;
        return {
          id: 300000 + id,
          username: id % 5 === 0 ? undefined : `user_${id}`,
          firstName: `First${id}`,
          lastName: `Last${id}`,
          role: r,
          banned: id % 11 === 0,
          lastSeenTs: Date.now() - randomInt(1, 3600 * 24 * 7) * 1000,
          messagesCount: randomInt(0, 800),
        };
      }).filter((u) => {
        const inQ =
          !q ||
          String(u.id).includes(q) ||
          (u.username && u.username.toLowerCase().includes(q.toLowerCase())) ||
          (u.firstName && u.firstName.toLowerCase().includes(q.toLowerCase())) ||
          (u.lastName && u.lastName.toLowerCase().includes(q.toLowerCase()));
        const inRole = role === "any" ? true : u.role === role;
        return inQ && inRole;
      });
      resolve({ items: users, total, limit, offset });
    }, 350)
  );
}

function mockUpdateUser(u: Partial<TelegramUser> & { id: number }): Promise<TelegramUser> {
  return new Promise((resolve, reject) =>
    setTimeout(() => {
      if (!u.id) return reject(new Error("Пользователь не найден"));
      resolve({
        id: u.id,
        username: u.username ?? `user_${u.id}`,
        firstName: u.firstName ?? "First",
        lastName: u.lastName ?? "Last",
        role: (u as any).role ?? "user",
        banned: (u as any).banned ?? false,
        lastSeenTs: Date.now(),
        messagesCount: randomInt(0, 1000),
      });
    }, 300)
  );
}

function mockLogs(level: LogLevel, limit: number): Promise<LogEntry[]> {
  const levels: LogLevel[] = ["debug", "info", "warn", "error"];
  return new Promise((resolve) =>
    setTimeout(() => {
      const now = Date.now();
      const arr: LogEntry[] = Array.from({ length: limit }, (_, i) => {
        const lv = levels[i % 4];
        return {
          id: `log-${now}-${i}`,
          ts: now - i * 5000,
          level: lv,
          message:
            lv === "error"
              ? "Ошибка доставки сообщения"
              : lv === "warn"
              ? "Замедление ответа Telegram"
              : lv === "debug"
              ? "Debug payload ok"
              : "Сообщение отправлено",
          meta: { requestId: `req-${i}`, chatId: 1000 + i },
        };
      }).filter((e) => (level ? e.level === level : true));
      resolve(arr);
    }, 300)
  );
}

function mockTestSend(p: TestSendPayload): Promise<{ ok: boolean; messageId?: number }> {
  return new Promise((resolve, reject) =>
    setTimeout(() => {
      if (!p.chatId || !p.text) return reject(new Error("chatId и текст обязательны"));
      resolve({ ok: true, messageId: randomInt(10000, 99999) });
    }, 500)
  );
}

function mockBroadcastStart(p: BroadcastPayload): Promise<BroadcastJob> {
  const id = `job-${Date.now()}`;
  return new Promise((resolve) =>
    setTimeout(
      () =>
        resolve({
          id,
          title: p.title,
          createdAt: Date.now(),
          total: 1200,
          processed: 0,
          success: 0,
          failed: 0,
          dryRun: p.dryRun,
          status: "queued",
        }),
      300
    )
  );
}

function mockBroadcastProgress(job: BroadcastJob): Promise<BroadcastJob> {
  return new Promise((resolve) =>
    setTimeout(() => {
      if (job.status === "done" || job.status === "failed" || job.status === "canceled") return resolve(job);
      const inc = randomInt(30, 120);
      const processed = Math.min(job.total, job.processed + inc);
      const success = Math.min(job.total, job.success + Math.floor(inc * 0.92));
      const failed = Math.max(0, processed - success);
      const status = processed >= job.total ? "done" : "running";
      resolve({
        ...job,
        startedAt: job.startedAt ?? Date.now(),
        processed,
        success,
        failed,
        status,
        finishedAt: status === "done" ? Date.now() : undefined,
      });
    }, 700)
  );
}

// ==============================
// Hooks
// ==============================
function usePolling<T>(fn: () => Promise<T>, enabled: boolean, ms: number) {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState<boolean>(enabled);
  const [error, setError] = useState<Error | null>(null);
  const timer = useRef<number | null>(null);

  const run = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await fn();
      setData(res);
    } catch (e: any) {
      setError(e);
    } finally {
      setLoading(false);
    }
  }, [fn]);

  useEffect(() => {
    if (!enabled) return;
    run();
  }, [enabled, run]);

  useEffect(() => {
    if (!enabled || !ms) return;
    timer.current = window.setInterval(run, ms);
    return () => {
      if (timer.current) window.clearInterval(timer.current);
    };
  }, [enabled, ms, run]);

  return { data, loading, error, refresh: run, setData };
}

// ==============================
// Component
// ==============================

const TelegramAdmin: FC = () => {
  // Config
  const [config, setConfig] = useState<TelegramBotConfig | null>(null);
  const [cfgLoading, setCfgLoading] = useState<boolean>(true);
  const [cfgError, setCfgError] = useState<Error | null>(null);
  const [showToken, setShowToken] = useState<boolean>(false);

  // Users
  const [uLimit, setULimit] = useState<number>(50);
  const [uOffset, setUOffset] = useState<number>(0);
  const [uQuery, setUQuery] = useState<string>("");
  const [uRole, setURole] = useState<SegRole>("any");
  const [usersPage, setUsersPage] = useState<FetchPage<TelegramUser> | null>(null);
  const [uLoading, setULoading] = useState<boolean>(true);
  const [uError, setUError] = useState<Error | null>(null);
  const debouncedQuery = useMemo(() => debounce((v: string) => setUQuery(v), 400), []);

  // Logs
  const [logLevel, setLogLevel] = useState<LogLevel>("info");
  const [autoLogs, setAutoLogs] = useState<boolean>(true);
  const { data: logs, loading: logsLoading, error: logsError, refresh: logsRefresh } = usePolling<LogEntry[]>(
    () => mockLogs(logLevel, 80),
    true,
    autoLogs ? 5000 : 0
  );

  // Test send
  const [testPayload, setTestPayload] = useState<TestSendPayload>({
    chatId: "",
    text: "",
    parseMode: "plain",
    linkPreview: false,
  });
  const [testSending, setTestSending] = useState<boolean>(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; messageId?: number; error?: string } | null>(null);

  // Broadcast
  const [bcPayload, setBcPayload] = useState<BroadcastPayload>({
    title: "",
    message: "",
    parseMode: "plain",
    dryRun: true,
    includeImageUrl: "",
    minMessages: 0,
    role: "any",
  });
  const [job, setJob] = useState<BroadcastJob | null>(null);
  const [autoJob, setAutoJob] = useState<boolean>(true);

  // Stats for chart from logs
  const traffic = useMemo(() => {
    const arr = logs ?? [];
    const buckets = new Map<string, number>();
    for (let i = 0; i < 24; i++) {
      const t = Date.now() - i * 60 * 60 * 1000;
      const key = fmtHour(t);
      buckets.set(key, 0);
    }
    arr.forEach((l) => {
      const key = fmtHour(l.ts);
      if (buckets.has(key)) buckets.set(key, (buckets.get(key) || 0) + 1);
    });
    return Array.from(buckets.entries())
      .map(([t, count]) => ({ t, count }))
      .reverse();
  }, [logs]);

  function fmtHour(ts: number) {
    const d = new Date(Math.floor(ts / (60 * 60 * 1000)) * (60 * 60 * 1000));
    return `${String(d.getHours()).padStart(2, "0")}:00`;
  }

  // Init config
  useEffect(() => {
    let active = true;
    setCfgLoading(true);
    mockConfig()
      .then((c) => active && setConfig(c))
      .catch((e) => active && setCfgError(e))
      .finally(() => active && setCfgLoading(false));
    return () => {
      active = false;
    };
  }, []);

  // Load users
  const loadUsers = useCallback(() => {
    setULoading(true);
    setUError(null);
    mockUsers(uLimit, uOffset, uQuery, uRole)
      .then(setUsersPage)
      .catch(setUError)
      .finally(() => setULoading(false));
  }, [uLimit, uOffset, uQuery, uRole]);

  useEffect(() => {
    loadUsers();
  }, [loadUsers]);

  // Track broadcast job
  useEffect(() => {
    if (!job || !autoJob) return;
    let stop = false;
    const t = window.setInterval(async () => {
      if (stop) return;
      const next = await mockBroadcastProgress(job);
      setJob(next);
      if (next.status === "done" || next.status === "failed" || next.status === "canceled") {
        window.clearInterval(t);
      }
    }, 1500);
    return () => {
      stop = true;
    };
  }, [job, autoJob]);

  // Actions
  const saveConfig = async () => {
    if (!config) return;
    // Local validation
    if (config.mode === "webhook" && !config.webhookUrl) {
      alert("Для режима webhook необходимо указать URL");
      return;
    }
    try {
      setCfgLoading(true);
      const saved = await mockSaveConfig(config);
      setConfig(saved);
    } catch (e: any) {
      setCfgError(e);
    } finally {
      setCfgLoading(false);
    }
  };

  const testSend = async () => {
    setTestSending(true);
    setTestResult(null);
    try {
      const res = await mockTestSend(testPayload);
      setTestResult(res);
    } catch (e: any) {
      setTestResult({ ok: false, error: e.message });
    } finally {
      setTestSending(false);
    }
  };

  const startBroadcast = async () => {
    if (!bcPayload.title || !bcPayload.message) {
      alert("Укажите заголовок и текст сообщения");
      return;
    }
    const started = await mockBroadcastStart(bcPayload);
    setJob(started);
  };

  const exportUsersCsv = () => {
    const rows =
      usersPage?.items.map((u) => ({
        id: u.id,
        username: u.username ?? "",
        firstName: u.firstName ?? "",
        lastName: u.lastName ?? "",
        role: u.role,
        banned: u.banned,
        lastSeen: fmtDate(u.lastSeenTs),
        messagesCount: u.messagesCount,
      })) ?? [];
    downloadCsv(`telegram-users-${Date.now()}.csv`, rows);
  };

  const updateUserRole = async (id: number, role: Role) => {
    const upd = await mockUpdateUser({ id, role });
    // optimistic update
    setUsersPage((prev) =>
      prev
        ? {
            ...prev,
            items: prev.items.map((x) => (x.id === id ? { ...x, role: upd.role } : x)),
          }
        : prev
    );
  };

  const toggleBan = async (id: number, banned: boolean) => {
    const upd = await mockUpdateUser({ id, banned });
    setUsersPage((prev) =>
      prev
        ? { ...prev, items: prev.items.map((x) => (x.id === id ? { ...x, banned: upd.banned } : x)) }
        : prev
    );
  };

  // Derived
  const statusBadge = config?.enabled ? (
    <Badge variant="outline" className="border-emerald-600 text-emerald-700">
      Включен
    </Badge>
  ) : (
    <Badge variant="outline" className="border-red-600 text-red-700">
      Выключен
    </Badge>
  );

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Telegram Admin</h1>
          <p className="text-sm text-muted-foreground">
            Управление интеграцией: настройки бота, тест-отправка, рассылки, пользователи, логи.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {statusBadge}
          <Button size="sm" variant="outline" onClick={() => logsRefresh()} aria-label="Обновить логи">
            <RefreshCcw className="mr-2 h-4 w-4" />
            Обновить логи
          </Button>
        </div>
      </div>

      {/* Config */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5" />
              Настройки бота
            </CardTitle>
            <CardDescription>Режим работы, вебхук, токен, ограничения.</CardDescription>
          </div>
          <div className="flex items-center gap-2">
            <Button size="sm" variant="outline" onClick={() => setConfig((c) => (c ? { ...c, enabled: !c.enabled } : c))}>
              {config?.enabled ? (
                <>
                  <Lock className="mr-2 h-4 w-4" />
                  Выключить
                </>
              ) : (
                <>
                  <PlayCircle className="mr-2 h-4 w-4" />
                  Включить
                </>
              )}
            </Button>
            <Button size="sm" onClick={saveConfig} disabled={cfgLoading}>
              {cfgLoading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Save className="mr-2 h-4 w-4" />}
              Сохранить
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {cfgLoading && !config ? (
            <Skeleton className="h-24 w-full" />
          ) : cfgError ? (
            <ErrorBox error={cfgError} onRetry={() => window.location.reload()} />
          ) : config ? (
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
              <div className="space-y-1.5">
                <Label>Режим</Label>
                <div className="flex items-center gap-3">
                  <Button
                    variant={config.mode === "webhook" ? "default" : "outline"}
                    size="sm"
                    onClick={() => setConfig({ ...config, mode: "webhook" })}
                  >
                    Webhook
                  </Button>
                  <Button
                    variant={config.mode === "polling" ? "default" : "outline"}
                    size="sm"
                    onClick={() => setConfig({ ...config, mode: "polling" })}
                  >
                    Polling
                  </Button>
                </div>
              </div>

              <div className="space-y-1.5 lg:col-span-2">
                <Label htmlFor="wh">Webhook URL</Label>
                <Input
                  id="wh"
                  placeholder="https://your-domain.tld/api/telegram/webhook"
                  value={config.webhookUrl ?? ""}
                  onChange={(e) => setConfig({ ...config, webhookUrl: e.target.value })}
                  disabled={config.mode !== "webhook"}
                />
              </div>

              <div className="space-y-1.5">
                <Label>Таймаут запроса (сек)</Label>
                <Input
                  type="number"
                  min={1}
                  max={60}
                  value={config.requestTimeoutSec}
                  onChange={(e) => setConfig({ ...config, requestTimeoutSec: Number(e.target.value || 0) })}
                />
              </div>

              <div className="space-y-1.5">
                <Label>Лимит сообщений в минуту</Label>
                <Input
                  type="number"
                  min={1}
                  max={10000}
                  value={config.rateLimitPerMin}
                  onChange={(e) => setConfig({ ...config, rateLimitPerMin: Number(e.target.value || 0) })}
                />
              </div>

              <div className="space-y-1.5">
                <Label>Имя бота</Label>
                <div className="flex gap-2">
                  <Input value={config.botUsername ?? ""} onChange={(e) => setConfig({ ...config, botUsername: e.target.value })} />
                  <Button variant="outline" size="icon" onClick={() => navigator.clipboard.writeText(config.botUsername || "")} aria-label="Скопировать username">
                    <Clipboard className="h-4 w-4" />
                  </Button>
                  <Button variant="outline" size="icon" asChild aria-label="Открыть в TG">
                    <a href={`https://t.me/${config.botUsername ?? ""}`} target="_blank" rel="noreferrer">
                      <ExternalLink className="h-4 w-4" />
                    </a>
                  </Button>
                </div>
              </div>

              <div className="space-y-1.5">
                <Label>Bot ID</Label>
                <div className="flex gap-2">
                  <Input value={config.botId ?? ""} onChange={(e) => setConfig({ ...config, botId: Number(e.target.value || 0) })} />
                  <Button variant="outline" size="icon" onClick={() => navigator.clipboard.writeText(String(config.botId ?? ""))} aria-label="Скопировать bot id">
                    <Clipboard className="h-4 w-4" />
                  </Button>
                </div>
              </div>

              <div className="space-y-1.5 lg:col-span-2">
                <Label>Token</Label>
                <div className="flex gap-2">
                  <Input
                    type={showToken ? "text" : "password"}
                    value={showToken ? config.tokenPlain ?? "" : config.tokenPlain ? maskToken(config.tokenPlain) : config.tokenMasked}
                    onChange={(e) => setConfig({ ...config, tokenPlain: e.target.value })}
                    placeholder="123456:ABC-..."
                  />
                  <Button variant="outline" size="icon" onClick={() => setShowToken((v) => !v)} aria-label="Показать/скрыть токен">
                    {showToken ? <EyeOff className="h-4 w-4" /> : <View className="h-4 w-4" />}
                  </Button>
                </div>
                <div className="text-xs text-muted-foreground">Хранится только в памяти браузера до сохранения.</div>
              </div>

              <div className="space-y-1.5 lg:col-span-2">
                <Label>Allowed updates</Label>
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button variant="outline" className="w-full justify-between">
                      Выбрано: {config.allowedUpdates.length}
                      <ChevronDown className="h-4 w-4" />
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent className="w-64">
                    <DropdownMenuLabel>Типы обновлений</DropdownMenuLabel>
                    <DropdownMenuSeparator />
                    {MOCK_ALLOWED.map((k) => (
                      <DropdownMenuCheckboxItem
                        key={k}
                        checked={config.allowedUpdates.includes(k)}
                        onCheckedChange={(v) =>
                          setConfig((c) =>
                            c
                              ? {
                                  ...c,
                                  allowedUpdates: v
                                    ? Array.from(new Set([...c.allowedUpdates, k]))
                                    : c.allowedUpdates.filter((x) => x !== k),
                                }
                              : c
                          )
                        }
                      >
                        {k}
                      </DropdownMenuCheckboxItem>
                    ))}
                  </DropdownMenuContent>
                </DropdownMenu>
              </div>
            </div>
          ) : null}
        </CardContent>
      </Card>

      {/* Live traffic chart */}
      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ListChecks className="h-5 w-5" />
              Активность за 24 часа
            </CardTitle>
            <CardDescription>Количество записей логов в час.</CardDescription>
          </CardHeader>
          <CardContent className="h-64">
            {logsLoading && !logs ? (
              <Skeleton className="h-full w-full" />
            ) : logsError ? (
              <ErrorBox error={logsError} onRetry={logsRefresh} />
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={traffic} margin={{ top: 10, right: 20, bottom: 0, left: 0 }}>
                  <defs>
                    <linearGradient id="lc" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopOpacity={0.6} />
                      <stop offset="95%" stopOpacity={0.1} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="t" />
                  <YAxis allowDecimals={false} />
                  <RechartsTooltip />
                  <Legend />
                  <Area type="monotone" dataKey="count" strokeWidth={2} fillOpacity={1} fill="url(#lc)" />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <SlidersHorizontal className="h-5 w-5" />
                Управление логами
              </CardTitle>
              <CardDescription>Автообновление и уровень.</CardDescription>
            </div>
            <Switch checked={autoLogs} onCheckedChange={setAutoLogs} />
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid grid-cols-4 gap-2">
              {(["debug", "info", "warn", "error"] as LogLevel[]).map((lv) => (
                <Button
                  key={lv}
                  variant={logLevel === lv ? "default" : "outline"}
                  onClick={() => setLogLevel(lv)}
                  size="sm"
                >
                  {lv}
                </Button>
              ))}
            </div>
            <div className="rounded-md border max-h-48 overflow-auto p-2 text-sm">
              {logsLoading && !logs ? (
                <Skeleton className="h-32 w-full" />
              ) : logsError ? (
                <ErrorBox error={logsError} onRetry={logsRefresh} />
              ) : (
                (logs ?? []).map((l) => (
                  <div key={l.id} className="flex items-start gap-2 py-1 border-b last:border-none">
                    {l.level === "error" ? (
                      <ShieldAlert className="h-4 w-4 text-red-600 mt-0.5" />
                    ) : l.level === "warn" ? (
                      <AlertCircle className="h-4 w-4 text-amber-600 mt-0.5" />
                    ) : l.level === "debug" ? (
                      <Shield className="h-4 w-4 text-slate-500 mt-0.5" />
                    ) : (
                      <ShieldCheck className="h-4 w-4 text-emerald-600 mt-0.5" />
                    )}
                    <div>
                      <div className="font-mono text-xs text-muted-foreground">{fmtDate(l.ts)}</div>
                      <div>{l.message}</div>
                      {l.meta ? <div className="text-xs text-muted-foreground">{JSON.stringify(l.meta)}</div> : null}
                    </div>
                  </div>
                ))
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Test send */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Send className="h-5 w-5" />
            Тест-отправка сообщения
          </CardTitle>
          <CardDescription>Проверьте доставку и форматирование.</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          <div className="space-y-1.5">
            <Label htmlFor="chatId">Chat ID</Label>
            <div className="flex gap-2">
              <Input
                id="chatId"
                placeholder="Например, 123456789"
                value={testPayload.chatId}
                onChange={(e) => setTestPayload((p) => ({ ...p, chatId: e.target.value }))}
              />
              <Button variant="outline" size="icon" onClick={() => navigator.clipboard.writeText(testPayload.chatId)} aria-label="Скопировать Chat ID">
                <Clipboard className="h-4 w-4" />
              </Button>
            </div>
          </div>

          <div className="space-y-1.5 lg:col-span-2">
            <Label htmlFor="text">Текст</Label>
            <Textarea
              id="text"
              placeholder="Ваше сообщение"
              value={testPayload.text}
              onChange={(e) => setTestPayload((p) => ({ ...p, text: e.target.value }))}
              rows={3}
            />
          </div>

          <div className="space-y-1.5">
            <Label>Parse mode</Label>
            <div className="flex gap-2">
              {(["plain", "markdown", "html"] as ParseMode[]).map((m) => (
                <Button
                  key={m}
                  size="sm"
                  variant={testPayload.parseMode === m ? "default" : "outline"}
                  onClick={() => setTestPayload((p) => ({ ...p, parseMode: m }))}
                >
                  {m}
                </Button>
              ))}
            </div>
          </div>

          <div className="space-y-1.5">
            <Label>Link preview</Label>
            <div className="flex items-center gap-3">
              <Switch checked={testPayload.linkPreview} onCheckedChange={(v) => setTestPayload((p) => ({ ...p, linkPreview: v }))} />
              <span className="text-sm text-muted-foreground">Разрешить предпросмотр ссылок</span>
            </div>
          </div>

          <div className="space-y-1.5 lg:col-span-1">
            <Label>Действие</Label>
            <div className="flex gap-2">
              <Button onClick={testSend} disabled={testSending}>
                {testSending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Send className="mr-2 h-4 w-4" />}
                Отправить
              </Button>
              {testResult ? (
                testResult.ok ? (
                  <Badge variant="outline" className="border-emerald-600 text-emerald-700">
                    OK #{testResult.messageId}
                  </Badge>
                ) : (
                  <Badge variant="outline" className="border-red-600 text-red-700">
                    Ошибка: {testResult.error}
                  </Badge>
                )
              ) : null}
            </div>
          </div>

          <div className="lg:col-span-2">
            <Label>Payload</Label>
            <pre className="mt-1 rounded-md border bg-muted/50 p-2 text-xs overflow-auto">
              {JSON.stringify(testPayload, null, 2)}
            </pre>
          </div>
        </CardContent>
      </Card>

      {/* Broadcast */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <CardTitle className="flex items-center gap-2">
              <Megaphone className="h-5 w-5" />
              Массовая рассылка
            </CardTitle>
            <CardDescription>Сегментация, dry-run, прогресс выполнения.</CardDescription>
          </div>
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2">
              <span className="text-sm text-muted-foreground">Авто-прогресс</span>
              <Switch checked={autoJob} onCheckedChange={setAutoJob} />
            </div>
            <Button onClick={startBroadcast}>
              <PlayCircle className="mr-2 h-4 w-4" />
              Запустить
            </Button>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            <div className="space-y-1.5">
              <Label>Заголовок</Label>
              <Input
                value={bcPayload.title}
                onChange={(e) => setBcPayload((p) => ({ ...p, title: e.target.value }))}
                placeholder="Имя рассылки"
              />
            </div>
            <div className="space-y-1.5">
              <Label>Роль</Label>
              <div className="flex gap-2">
                {(["any", "admin", "moderator", "user"] as SegRole[]).map((r) => (
                  <Button
                    key={r}
                    size="sm"
                    variant={bcPayload.role === r ? "default" : "outline"}
                    onClick={() => setBcPayload((p) => ({ ...p, role: r }))}
                  >
                    {r}
                  </Button>
                ))}
              </div>
            </div>
            <div className="space-y-1.5">
              <Label>Мин. сообщений у пользователя</Label>
              <Input
                type="number"
                min={0}
                value={bcPayload.minMessages ?? 0}
                onChange={(e) => setBcPayload((p) => ({ ...p, minMessages: Number(e.target.value || 0) }))}
              />
            </div>

            <div className="space-y-1.5 lg:col-span-2">
              <Label>Текст</Label>
              <Textarea
                value={bcPayload.message}
                onChange={(e) => setBcPayload((p) => ({ ...p, message: e.target.value }))}
                rows={4}
                placeholder="Контент сообщения"
              />
            </div>

            <div className="space-y-1.5">
              <Label>Parse mode</Label>
              <div className="flex gap-2">
                {(["plain", "markdown", "html"] as ParseMode[]).map((m) => (
                  <Button
                    key={m}
                    size="sm"
                    variant={bcPayload.parseMode === m ? "default" : "outline"}
                    onClick={() => setBcPayload((p) => ({ ...p, parseMode: m }))}
                  >
                    {m}
                  </Button>
                ))}
              </div>
              <div className="mt-3 flex items-center gap-2">
                <Switch checked={bcPayload.dryRun} onCheckedChange={(v) => setBcPayload((p) => ({ ...p, dryRun: v }))} />
                <span className="text-sm text-muted-foreground">Dry-run (без фактической отправки)</span>
              </div>
            </div>

            <div className="space-y-1.5">
              <Label>Ссылка на изображение (опционально)</Label>
              <Input
                placeholder="https://…/image.jpg"
                value={bcPayload.includeImageUrl ?? ""}
                onChange={(e) => setBcPayload((p) => ({ ...p, includeImageUrl: e.target.value }))}
              />
            </div>
          </div>

          {job ? (
            <div className="rounded-xl border p-4">
              <div className="flex items-center justify-between">
                <div className="font-medium">{job.title}</div>
                <Badge variant="outline">{job.status}</Badge>
              </div>
              <div className="mt-3">
                <Progress value={(job.processed / job.total) * 100} className="h-2" />
                <div className="mt-2 text-xs text-muted-foreground">
                  {job.processed}/{job.total} • ok: {job.success} • fail: {job.failed} • {job.dryRun ? "DRY-RUN" : "REAL"}
                </div>
              </div>
            </div>
          ) : null}
        </CardContent>
      </Card>

      {/* Users */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0">
          <div>
            <CardTitle className="flex items-center gap-2">
              <Users className="h-5 w-5" />
              Пользователи
              <Badge variant="outline">{usersPage?.total?.toLocaleString() ?? 0} всего</Badge>
            </CardTitle>
            <CardDescription>Поиск, роли, бан, экспорт CSV.</CardDescription>
          </div>
          <div className="flex items-center gap-2">
            <Button size="sm" variant="outline" onClick={exportUsersCsv}>
              <Download className="mr-2 h-4 w-4" />
              Экспорт CSV
            </Button>
            <Button size="sm" variant="outline">
              <Upload className="mr-2 h-4 w-4" />
              Импорт CSV
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-4">
            <div className="relative">
              <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                className="pl-8"
                placeholder="ID, username, имя, фамилия"
                onChange={(e) => debouncedQuery(e.target.value)}
                aria-label="Поиск пользователей"
              />
            </div>
            <div className="flex items-center gap-2">
              <Label>Роль</Label>
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="outline">
                    {uRole} <ChevronDown className="ml-2 h-4 w-4" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent>
                  {(["any", "admin", "moderator", "user"] as SegRole[]).map((r) => (
                    <DropdownMenuItem key={r} onClick={() => setURole(r)}>
                      {r}
                    </DropdownMenuItem>
                  ))}
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
            <div className="flex items-center gap-2">
              <Label>На странице</Label>
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="outline">
                    {uLimit} <ChevronDown className="ml-2 h-4 w-4" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent>
                  {[25, 50, 100, 200].map((n) => (
                    <DropdownMenuItem
                      key={n}
                      onClick={() => {
                        setULimit(n);
                        setUOffset(0);
                      }}
                    >
                      {n}
                    </DropdownMenuItem>
                  ))}
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
            <div className="flex items-center justify-end gap-2">
              <Button variant="outline" size="sm" onClick={() => setUOffset(Math.max(0, uOffset - uLimit))} disabled={uOffset === 0}>
                Назад
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setUOffset(uOffset + uLimit)}
                disabled={(usersPage?.offset ?? 0) + (usersPage?.items.length ?? 0) >= (usersPage?.total ?? 0)}
              >
                Вперед
              </Button>
            </div>
          </div>

          <div className="mt-4 rounded-md border overflow-x-auto">
            <Table>
              <TableCaption>
                Показаны {uOffset + 1}–{Math.min(uOffset + uLimit, usersPage?.total ?? 0)} из {usersPage?.total ?? 0}
              </TableCaption>
              <TableHeader>
                <TableRow>
                  <TableHead>ID</TableHead>
                  <TableHead>Username</TableHead>
                  <TableHead>Имя</TableHead>
                  <TableHead>Фамилия</TableHead>
                  <TableHead>Роль</TableHead>
                  <TableHead>Бан</TableHead>
                  <TableHead>Last seen</TableHead>
                  <TableHead>Msg</TableHead>
                  <TableHead className="w-[1%]">Действия</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {uLoading && !usersPage ? (
                  Array.from({ length: 8 }).map((_, i) => (
                    <TableRow key={`s-${i}`}>
                      {Array.from({ length: 9 }).map((__, j) => (
                        <TableCell key={j}>
                          <Skeleton className="h-5 w-full" />
                        </TableCell>
                      ))}
                    </TableRow>
                  ))
                ) : uError ? (
                  <TableRow>
                    <TableCell colSpan={9}>
                      <ErrorBox error={uError} onRetry={loadUsers} />
                    </TableCell>
                  </TableRow>
                ) : (usersPage?.items?.length ?? 0) === 0 ? (
                  <TableRow>
                    <TableCell colSpan={9}>
                      <div className="py-8 text-center text-sm text-muted-foreground">Пользователи не найдены.</div>
                    </TableCell>
                  </TableRow>
                ) : (
                  usersPage!.items.map((u) => (
                    <TableRow key={u.id} className="hover:bg-muted/40">
                      <TableCell className="font-mono">{u.id}</TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <AtSign className="h-4 w-4" />
                          {u.username ? u.username : <span className="text-muted-foreground">нет</span>}
                        </div>
                      </TableCell>
                      <TableCell>{u.firstName}</TableCell>
                      <TableCell>{u.lastName}</TableCell>
                      <TableCell>
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="outline" size="sm">
                              {u.role} <ChevronDown className="ml-2 h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent>
                            {(["admin", "moderator", "user"] as Role[]).map((r) => (
                              <DropdownMenuItem key={r} onClick={() => updateUserRole(u.id, r)}>
                                {r}
                              </DropdownMenuItem>
                            ))}
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </TableCell>
                      <TableCell>
                        <Switch checked={u.banned} onCheckedChange={(v) => toggleBan(u.id, v)} />
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">{fmtDate(u.lastSeenTs)}</TableCell>
                      <TableCell>{u.messagesCount}</TableCell>
                      <TableCell>
                        <div className="flex items-center gap-1">
                          <Button variant="outline" size="icon" aria-label="Написать пользователю">
                            <Mail className="h-4 w-4" />
                          </Button>
                          <Button variant="outline" size="icon" aria-label="Редактировать">
                            <Edit3 className="h-4 w-4" />
                          </Button>
                          <Button variant="outline" size="icon" aria-label="Удалить">
                            <Trash2 className="h-4 w-4" />
                          </Button>
                          {u.banned ? (
                            <Badge variant="outline" className="border-red-600 text-red-700">
                              <Ban className="mr-1 h-3 w-3" />
                              banned
                            </Badge>
                          ) : null}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Footer / tabs */}
      <Card>
        <CardContent className="pt-6">
          <Tabs defaultValue="status">
            <TabsList className="grid w-full grid-cols-3">
              <TabsTrigger value="status" className="flex items-center gap-2">
                <CheckCircle2 className="h-4 w-4" /> Статус
              </TabsTrigger>
              <TabsTrigger value="help" className="flex items-center gap-2">
                <ExternalLink className="h-4 w-4" /> Справка
              </TabsTrigger>
              <TabsTrigger value="actions" className="flex items-center gap-2">
                <History className="h-4 w-4" /> Действия
              </TabsTrigger>
            </TabsList>
            <TabsContent value="status" className="space-y-2">
              <div className="grid gap-2 md:grid-cols-3">
                <StatusTile title="Интеграция" value={config?.enabled ? "Включена" : "Выключена"} description="Состояние коннектора" icon={<ShieldCheck className="h-4 w-4" />} />
                <StatusTile title="Режим" value={config?.mode ?? "—"} description="Webhook / Polling" icon={<SlidersHorizontal className="h-4 w-4" />} />
                <StatusTile title="Rate limit" value={`${config?.rateLimitPerMin ?? 0}/мин`} description="Ограничение отправки" icon={<ListChecks className="h-4 w-4" />} />
              </div>
            </TabsContent>
            <TabsContent value="help" className="text-sm text-muted-foreground">
              Этот интерфейс предназначен для управления Telegram-интеграцией. Реальные вызовы API должны быть реализованы на бэкенде. В этом файле используются мок-функции.
            </TabsContent>
            <TabsContent value="actions" className="text-sm text-muted-foreground">
              История действий может быть добавлена через аудит-лог бэкенда.
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};

// ==============================
// Subcomponents
// ==============================
const ErrorBox: FC<{ error: Error; onRetry: () => void }> = ({ error, onRetry }) => {
  return (
    <div className="flex items-center justify-between rounded-md border border-destructive/40 bg-destructive/10 p-3">
      <div className="flex items-center gap-2">
        <AlertCircle className="h-4 w-4 text-destructive" />
        <div className="text-sm">
          <div className="font-medium">Ошибка</div>
          <div className="text-muted-foreground">{error.message}</div>
        </div>
      </div>
      <Button size="sm" variant="outline" onClick={onRetry}>
        Повторить
      </Button>
    </div>
  );
};

const StatusTile: FC<{ title: string; value: string; description: string; icon: React.ReactNode }> = ({
  title,
  value,
  description,
  icon,
}) => {
  return (
    <div className="rounded-2xl border p-4 shadow-sm">
      <div className="flex items-center justify-between">
        <div className="text-sm text-muted-foreground">{title}</div>
        <div>{icon}</div>
      </div>
      <div className="mt-1 text-xl font-semibold">{value}</div>
      <div className="text-xs text-muted-foreground">{description}</div>
    </div>
  );
};

export default TelegramAdmin;
