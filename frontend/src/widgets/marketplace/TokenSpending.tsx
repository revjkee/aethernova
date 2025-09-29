// frontend/src/widgets/Marketplace/TokenSpending.tsx
import * as React from "react";
import { useEffect, useMemo, useState, useTransition } from "react";
import { z } from "zod";

/**
 * UI primitives: shadcn/ui (fallbacks provided for minimal portability)
 * Replace fallbacks with your local imports if you already have shadcn/ui set up:
 *   import { Card, CardHeader, CardTitle, CardContent, CardFooter } from "@/components/ui/card";
 *   import { Button } from "@/components/ui/button";
 *   import { Input } from "@/components/ui/input";
 *   import { Label } from "@/components/ui/label";
 *   import { Select, SelectTrigger, SelectValue, SelectContent, SelectItem } from "@/components/ui/select";
 */
type DivProps = React.HTMLAttributes<HTMLDivElement>;
const cn = (...xs: Array<string | false | undefined | null>) => xs.filter(Boolean).join(" ");

const Card = ({ className, ...p }: DivProps) => <div className={cn("rounded-2xl border bg-card text-card-foreground shadow-sm", className)} {...p} />;
const CardHeader = ({ className, ...p }: DivProps) => <div className={cn("p-6 border-b", className)} {...p} />;
const CardTitle = ({ className, ...p }: DivProps) => <h3 className={cn("text-xl font-semibold", className)} {...p} />;
const CardContent = ({ className, ...p }: DivProps) => <div className={cn("p-6 space-y-4", className)} {...p} />;
const CardFooter = ({ className, ...p }: DivProps) => <div className={cn("p-6 border-t", className)} {...p} />;

const Button = ({ className, disabled, ...p }: React.ButtonHTMLAttributes<HTMLButtonElement>) => (
  <button
    className={cn(
      "inline-flex items-center justify-center rounded-xl px-4 py-2 text-sm font-medium ring-offset-background transition-colors",
      disabled ? "bg-muted text-muted-foreground cursor-not-allowed" : "bg-primary text-primary-foreground hover:opacity-90",
      className
    )}
    disabled={disabled}
    {...p}
  />
);

const Input = ({ className, ...p }: React.InputHTMLAttributes<HTMLInputElement>) => (
  <input
    className={cn(
      "flex h-10 w-full rounded-xl border bg-background px-3 py-2 text-sm ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary",
      className
    )}
    {...p}
  />
);

const Label = ({ className, ...p }: React.LabelHTMLAttributes<HTMLLabelElement>) => (
  <label className={cn("text-sm font-medium", className)} {...p} />
);

// Minimal accessible Select (fallback). Replace with shadcn Select if available.
function SelectBase({
  value,
  onValueChange,
  children,
  className,
  "aria-label": ariaLabel,
}: {
  value: string | undefined;
  onValueChange: (v: string) => void;
  children: React.ReactNode;
  className?: string;
  "aria-label"?: string;
}) {
  return (
    <select
      aria-label={ariaLabel}
      className={cn("h-10 w-full rounded-xl border bg-background px-3 py-2 text-sm", className)}
      value={value}
      onChange={(e) => onValueChange(e.target.value)}
    >
      {children}
    </select>
  );
}

const numberFmt = (locale = "en-US", maximumFractionDigits = 6) =>
  new Intl.NumberFormat(locale, { minimumFractionDigits: 0, maximumFractionDigits });

/* ============================== Types & Contracts ============================== */

export type Chain = {
  id: number;
  name: string;
  rpcLabel?: string;
};

export type Token = {
  symbol: string;
  name: string;
  address: string; // "0x..." or native sentinel like "native"
  decimals: number;
};

export type SpendRecord = {
  id: string;
  timestamp: number; // ms
  chainId: number;
  token: string; // symbol
  amountUnits: bigint; // smallest units
  memo?: string;
  txHash?: string;
  status: "pending" | "confirmed" | "failed";
};

export interface WalletAdapter {
  getChainId(): Promise<number>;
  switchChain(chainId: number): Promise<void>;
  getBalance(chainId: number, token: Token, account?: string): Promise<bigint>;
  getAllowance(chainId: number, token: Token, owner: string, spender: string): Promise<bigint>;
  approve(chainId: number, token: Token, spender: string, amountUnits: bigint): Promise<string>; // returns tx hash
  spend(chainId: number, token: Token, spender: string, amountUnits: bigint, memo?: string): Promise<string>; // returns tx hash
  getAccount(): Promise<string>;
}

export type TokenSpendingProps = {
  title?: string;
  chains: Chain[];
  tokens: Token[];
  spender: string; // marketplace contract address
  wallet: WalletAdapter;
  defaultChainId?: number;
  defaultTokenSymbol?: string;
  locale?: string;
  minimumApproveUnits?: bigint; // if omitted, approve exact amount
  history?: SpendRecord[]; // initial history
  maxHistory?: number; // default 50
  onSpent?: (record: SpendRecord) => void;
  onError?: (err: Error) => void;
};

/* ============================== Validation & Math ============================== */

const spendSchema = z.object({
  amount: z
    .string()
    .trim()
    .refine((v) => /^[0-9]+(\.[0-9]{1,18})?$/.test(v), "Введите корректную сумму"),
  memo: z.string().trim().max(280).optional(),
});

function pow10(decimals: number): bigint {
  let r = 1n;
  for (let i = 0; i < decimals; i++) r *= 10n;
  return r;
}

function parseAmountToUnits(amount: string, decimals: number): bigint {
  // safe parsing without floats
  const [intPart, fracRaw] = amount.split(".");
  const frac = (fracRaw ?? "").slice(0, decimals);
  const fracPadded = frac + "0".repeat(decimals - frac.length);
  const unitsStr = (intPart || "0") + fracPadded;
  // strip leading zeros
  const clean = unitsStr.replace(/^0+(?=\d)/, "");
  return BigInt(clean.length ? clean : "0");
}

function formatUnits(units: bigint, decimals: number, locale = "en-US", maximumFractionDigits = 6): string {
  const base = pow10(decimals);
  const int = units / base;
  const frac = units % base;
  if (frac === 0n) return numberFmt(locale, 0).format(Number(int));
  const fracStr = frac.toString().padStart(decimals, "0").replace(/0+$/, "");
  const merged = `${int.toString()}.${fracStr}`;
  // Clamp displayed fraction digits
  const [i, f] = merged.split(".");
  const shownFrac = (f ?? "").slice(0, maximumFractionDigits);
  const numeric = Number(`${i}.${shownFrac || "0"}`);
  return numberFmt(locale, shownFrac ? shownFrac.length : 0).format(numeric);
}

/* ============================== Component ============================== */

export default function TokenSpending({
  title = "Token Spending",
  chains,
  tokens,
  spender,
  wallet,
  defaultChainId,
  defaultTokenSymbol,
  locale = "en-US",
  minimumApproveUnits,
  history = [],
  maxHistory = 50,
  onSpent,
  onError,
}: TokenSpendingProps) {
  const [isPending, startTransition] = useTransition();

  const [chainId, setChainId] = useState<number | undefined>(defaultChainId);
  const [tokenSymbol, setTokenSymbol] = useState<string | undefined>(defaultTokenSymbol ?? tokens[0]?.symbol);
  const token = useMemo(() => tokens.find((t) => t.symbol === tokenSymbol), [tokens, tokenSymbol]);

  const [account, setAccount] = useState<string>("");
  const [balanceUnits, setBalanceUnits] = useState<bigint>(0n);
  const [allowanceUnits, setAllowanceUnits] = useState<bigint>(0n);

  const [form, setForm] = useState<{ amount: string; memo?: string }>({ amount: "" });
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [localHistory, setLocalHistory] = useState<SpendRecord[]>(history.slice(-maxHistory));

  /* ------------------------------ Effects ------------------------------ */

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const cid = await wallet.getChainId();
        if (!cancelled) setChainId(defaultChainId ?? cid);
        const acc = await wallet.getAccount();
        if (!cancelled) setAccount(acc);
      } catch (e) {
        if (onError && e instanceof Error) onError(e);
      }
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Refresh balance and allowance
  useEffect(() => {
    if (!chainId || !token || !account) return;
    let cancelled = false;
    (async () => {
      try {
        const [bal, alw] = await Promise.all([
          wallet.getBalance(chainId, token, account),
          wallet.getAllowance(chainId, token, account, spender),
        ]);
        if (!cancelled) {
          setBalanceUnits(bal);
          setAllowanceUnits(alw);
        }
      } catch (e) {
        if (onError && e instanceof Error) onError(e);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [chainId, token, account, spender, wallet, localHistory.length, onError]);

  /* ------------------------------ Derived ------------------------------ */

  const amountUnits: bigint = useMemo(() => {
    if (!token?.decimals || !form.amount) return 0n;
    try {
      return parseAmountToUnits(form.amount, token.decimals);
    } catch {
      return 0n;
    }
  }, [form.amount, token?.decimals]);

  const needsApproval = useMemo(() => {
    if (!token) return false;
    if (amountUnits === 0n) return false;
    return allowanceUnits < amountUnits;
  }, [allowanceUnits, amountUnits, token]);

  const insufficientBalance = useMemo(() => {
    if (amountUnits === 0n) return false;
    return balanceUnits < amountUnits;
  }, [balanceUnits, amountUnits]);

  /* ------------------------------ Handlers ------------------------------ */

  async function handleSwitchChain(nextId: number) {
    try {
      await wallet.switchChain(nextId);
      setChainId(nextId);
    } catch (e) {
      if (onError && e instanceof Error) onError(e);
    }
  }

  function validate(): boolean {
    const res = spendSchema.safeParse(form);
    if (!res.success) {
      const errs: Record<string, string> = {};
      for (const issue of res.error.issues) {
        const path = issue.path.join(".") || "amount";
        errs[path] = issue.message;
      }
      setErrors(errs);
      return false;
    }
    setErrors({});
    if (amountUnits <= 0n) {
      setErrors({ amount: "Сумма должна быть больше нуля" });
      return false;
    }
    if (insufficientBalance) {
      setErrors({ amount: "Недостаточно средств" });
      return false;
    }
    return true;
  }

  function pushHistory(rec: SpendRecord) {
    setLocalHistory((h) => {
      const next = [...h, rec].slice(-maxHistory);
      return next.sort((a, b) => a.timestamp - b.timestamp);
    });
    onSpent?.(rec);
  }

  async function handleApprove() {
    if (!token || !chainId) return;
    if (!validate()) return;
    const approveAmount = minimumApproveUnits && minimumApproveUnits > amountUnits ? minimumApproveUnits : amountUnits;
    startTransition(() => {});
    try {
      const txHash = await wallet.approve(chainId, token, spender, approveAmount);
      // Optimistic bump of allowance
      setAllowanceUnits((x) => (x + approveAmount));
      pushHistory({
        id: `approve:${Date.now()}`,
        timestamp: Date.now(),
        chainId,
        token: token.symbol,
        amountUnits: approveAmount,
        memo: "approve",
        txHash,
        status: "pending",
      });
    } catch (e) {
      if (onError && e instanceof Error) onError(e);
    }
  }

  async function handleSpend() {
    if (!token || !chainId) return;
    if (!validate()) return;
    startTransition(() => {});
    const optimistic: SpendRecord = {
      id: `spend:${Date.now()}`,
      timestamp: Date.now(),
      chainId,
      token: token.symbol,
      amountUnits,
      memo: form.memo,
      status: "pending",
    };
    pushHistory(optimistic);
    try {
      const txHash = await wallet.spend(chainId, token, spender, amountUnits, form.memo);
      // optimistic balance decrease
      setBalanceUnits((b) => (b >= amountUnits ? b - amountUnits : b));
      // update history record to confirmed
      setLocalHistory((h) =>
        h.map((r) => (r.id === optimistic.id ? { ...r, txHash, status: "confirmed" } : r))
      );
      // reduce allowance if allowance is tracked as decreasing (depends on token standard; kept conservative)
      setAllowanceUnits((a) => (a >= amountUnits ? a - amountUnits : a));
    } catch (e) {
      setLocalHistory((h) => h.map((r) => (r.id === optimistic.id ? { ...r, status: "failed" } : r)));
      if (onError && e instanceof Error) onError(e);
    }
  }

  /* ------------------------------ Render ------------------------------ */

  return (
    <Card className="w-full max-w-3xl">
      <CardHeader>
        <CardTitle>{title}</CardTitle>
      </CardHeader>

      <CardContent>
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          {/* Chain select */}
          <div className="space-y-2">
            <Label htmlFor="chain">Сеть</Label>
            <SelectBase
              aria-label="Выбор сети"
              value={String(chainId ?? "")}
              onValueChange={(v) => handleSwitchChain(Number(v))}
            >
              <option value="" disabled>
                Выберите сеть
              </option>
              {chains.map((c) => (
                <option key={c.id} value={String(c.id)}>
                  {c.name}
                </option>
              ))}
            </SelectBase>
          </div>

          {/* Token select */}
          <div className="space-y-2">
            <Label htmlFor="token">Токен</Label>
            <SelectBase
              aria-label="Выбор токена"
              value={tokenSymbol}
              onValueChange={(v) => setTokenSymbol(v)}
            >
              {tokens.map((t) => (
                <option key={t.symbol} value={t.symbol}>
                  {t.symbol} — {t.name}
                </option>
              ))}
            </SelectBase>
          </div>

          {/* Amount */}
          <div className="space-y-2">
            <Label htmlFor="amount">Сумма</Label>
            <Input
              id="amount"
              inputMode="decimal"
              placeholder="0.0"
              value={form.amount}
              onChange={(e) => setForm((f) => ({ ...f, amount: e.target.value }))}
              aria-invalid={!!errors.amount}
              aria-describedby={errors.amount ? "amount-error" : undefined}
            />
            {errors.amount && (
              <p id="amount-error" className="text-sm text-red-600">
                {errors.amount}
              </p>
            )}
            <p className="text-xs text-muted-foreground">
              Баланс:{" "}
              {token
                ? `${formatUnits(balanceUnits, token.decimals, locale)} ${token.symbol}`
                : "-"}
            </p>
          </div>

          {/* Memo */}
          <div className="space-y-2">
            <Label htmlFor="memo">Описание (необязательно)</Label>
            <Input
              id="memo"
              maxLength={280}
              placeholder="Назначение платежа"
              value={form.memo ?? ""}
              onChange={(e) => setForm((f) => ({ ...f, memo: e.target.value }))}
            />
          </div>
        </div>

        {/* Allowance / Status */}
        <div className="mt-4 grid grid-cols-1 gap-4 md:grid-cols-3">
          <div className="rounded-xl border p-4">
            <div className="text-sm text-muted-foreground">Необходимо к списанию</div>
            <div className="text-lg font-semibold">
              {token ? `${formatUnits(amountUnits, token.decimals, locale)} ${token.symbol}` : "-"}
            </div>
          </div>
          <div className="rounded-xl border p-4">
            <div className="text-sm text-muted-foreground">Доступно (allowance)</div>
            <div className={cn("text-lg font-semibold", needsApproval && "text-amber-600")}>
              {token ? `${formatUnits(allowanceUnits, token.decimals, locale)} ${token.symbol}` : "-"}
            </div>
          </div>
          <div className="rounded-xl border p-4">
            <div className="text-sm text-muted-foreground">Статус</div>
            <div
              className={cn(
                "text-lg font-semibold",
                insufficientBalance ? "text-red-600" : needsApproval ? "text-amber-600" : "text-emerald-600"
              )}
            >
              {insufficientBalance ? "Недостаточно средств" : needsApproval ? "Нужна апрув" : "Готово к оплате"}
            </div>
          </div>
        </div>
      </CardContent>

      <CardFooter className="flex flex-col gap-3 md:flex-row md:justify-between">
        <div className="flex items-center gap-2">
          <Button
            onClick={handleApprove}
            disabled={isPending || !token || !chainId || !needsApproval || amountUnits === 0n}
            aria-disabled={isPending || !token || !chainId || !needsApproval || amountUnits === 0n}
          >
            {isPending ? "Обработка..." : "Approve"}
          </Button>
          <Button
            onClick={handleSpend}
            disabled={isPending || !token || !chainId || needsApproval || amountUnits === 0n || insufficientBalance}
            aria-disabled={isPending || !token || !chainId || needsApproval || amountUnits === 0n || insufficientBalance}
            className="bg-emerald-600 text-white hover:opacity-90"
          >
            {isPending ? "Отправка..." : "Spend"}
          </Button>
        </div>

        {/* Summary */}
        <div className="text-sm text-muted-foreground">
          Аккаунт: <span className="font-mono">{account ? truncateAddr(account) : "-"}</span>{" "}
          {token && (
            <>
              • Баланс: <span className="font-mono">{formatUnits(balanceUnits, token.decimals, locale)}</span>{" "}
              {token.symbol}
            </>
          )}
        </div>
      </CardFooter>

      {/* History */}
      <CardContent>
        <h4 className="text-sm font-medium">История</h4>
        <div className="mt-2 divide-y rounded-xl border">
          {localHistory.length === 0 && <div className="p-4 text-sm text-muted-foreground">Пока нет операций</div>}
          {localHistory
            .slice()
            .reverse()
            .map((r) => (
              <div key={r.id} className="flex flex-col gap-2 p-4 md:flex-row md:items-center md:justify-between">
                <div className="flex flex-col">
                  <span className="text-sm">
                    {new Date(r.timestamp).toLocaleString(locale)} • Chain {r.chainId}
                  </span>
                  <span className="text-sm font-medium">
                    {r.token} {tokenBySymbol(tokens, r.token)?.decimals != null
                      ? formatUnits(r.amountUnits, tokenBySymbol(tokens, r.token)!.decimals, locale)
                      : r.amountUnits.toString()}
                  </span>
                  {r.memo && <span className="text-xs text-muted-foreground">Memo: {r.memo}</span>}
                </div>
                <div className="flex items-center gap-3">
                  <StatusPill status={r.status} />
                  <code className="rounded bg-muted px-2 py-1 text-xs">{r.txHash ? truncateHash(r.txHash) : "-"}</code>
                </div>
              </div>
            ))}
        </div>
      </CardContent>
    </Card>
  );
}

/* ============================== Helpers ============================== */

function tokenBySymbol(tokens: Token[], sym: string): Token | undefined {
  return tokens.find((t) => t.symbol === sym);
}

function truncateAddr(addr: string, size = 4): string {
  if (addr.length <= 2 * size) return addr;
  return `${addr.slice(0, 2 + size)}…${addr.slice(-size)}`;
}

function truncateHash(h: string, size = 6): string {
  if (h.length <= 2 * size) return h;
  return `${h.slice(0, size)}…${h.slice(-size)}`;
}

/* ============================== Example Mock Adapter (Optional) ============================== */
/**
 * NOTE: This is a safe mock for local development. Remove in production.
 * It simulates wallet behavior with in-memory state.
 */
export class InMemoryWallet implements WalletAdapter {
  private _chainId: number;
  private _account: string;
  private balances = new Map<string, bigint>();
  private allowances = new Map<string, bigint>();

  constructor(opts: { chainId: number; account?: string; seed?: Array<{ key: string; value: bigint }> } = { chainId: 1 }) {
    this._chainId = opts.chainId;
    this._account = opts.account ?? "0x0000000000000000000000000000000000000000";
    opts.seed?.forEach(({ key, value }) => this.balances.set(key, value));
  }

  key(chainId: number, token: Token) {
    return `${chainId}:${token.symbol}:balance`;
  }
  keyAlw(chainId: number, token: Token, spender: string) {
    return `${chainId}:${token.symbol}:${spender}:allowance`;
  }

  async getChainId(): Promise<number> {
    return this._chainId;
  }
  async switchChain(chainId: number): Promise<void> {
    this._chainId = chainId;
  }
  async getBalance(chainId: number, token: Token): Promise<bigint> {
    return this.balances.get(this.key(chainId, token)) ?? 0n;
    }
  async getAllowance(chainId: number, token: Token, _owner: string, spender: string): Promise<bigint> {
    return this.allowances.get(this.keyAlw(chainId, token, spender)) ?? 0n;
  }
  async approve(chainId: number, token: Token, spender: string, amountUnits: bigint): Promise<string> {
    const k = this.keyAlw(chainId, token, spender);
    const prev = this.allowances.get(k) ?? 0n;
    this.allowances.set(k, prev + amountUnits);
    return `0xapprove${Date.now().toString(16)}`;
  }
  async spend(chainId: number, token: Token, _spender: string, amountUnits: bigint, _memo?: string): Promise<string> {
    const k = this.key(chainId, token);
    const bal = this.balances.get(k) ?? 0n;
    if (bal < amountUnits) throw new Error("INSUFFICIENT_FUNDS");
    this.balances.set(k, bal - amountUnits);
    return `0xspend${Date.now().toString(16)}`;
  }
  async getAccount(): Promise<string> {
    return this._account;
  }
}
