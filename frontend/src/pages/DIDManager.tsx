import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { motion } from "framer-motion";

// Helper function to replace date-fns format
const formatDate = (date: Date | string | number, formatString: string) => {
  const d = new Date(date);
  if (formatString === "PPpp") {
    return d.toLocaleString();
  }
  return d.toISOString().slice(0, 19).replace('T', ' ');
};
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
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuShortcut,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useToast } from "@/components/ui/use-toast";
import { cn } from "@/lib/utils";
import {
  Check,
  Copy,
  Download,
  FileJson,
  Fingerprint,
  KeyRound,
  LinkIcon,
  Loader2,
  MoreHorizontal,
  Plus,
  RefreshCw,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  Trash2,
} from "lucide-react";

// ------------------------------------------------------
// Types
// ------------------------------------------------------

type DidMethod = "did:web" | "did:key" | "did:example";

type KeyAlgo = "ECDSA_P256" | "RSA_PSS"; // реализуем через SubtleCrypto

type DidStatus = "active" | "revoked";

type DidRecord = {
  id: string; // DID string
  method: DidMethod;
  createdAt: number;
  updatedAt: number;
  status: DidStatus;
  algo: KeyAlgo;
  controller: string; // same as id (self-controlled)
  publicKeyJwk: JsonWebKey;
  kid: string; // key id fragment
  isDefault?: boolean;
};

type DidDocument = {
  id: string;
  controller: string;
  verificationMethod: Array<{
    id: string;
    type: string;
    controller: string;
    publicKeyJwk: JsonWebKey;
  }>;
  authentication: string[];
  assertionMethod: string[];
};

// ------------------------------------------------------
// Local Storage Provider
// ------------------------------------------------------

const STORAGE_KEY = "did-manager.records.v1";
const PRIVKEY_PREFIX = "did-manager.private."; // per-kid protected by origin storage

const persistRecords = (arr: DidRecord[]) => {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(arr));
};

const loadRecords = (): DidRecord[] => {
  const raw = localStorage.getItem(STORAGE_KEY);
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw) as DidRecord[];
    return parsed;
  } catch {
    return [];
  }
};

const savePrivateKey = async (kid: string, key: CryptoKey) => {
  const jwk = await crypto.subtle.exportKey("jwk", key);
  localStorage.setItem(PRIVKEY_PREFIX + kid, JSON.stringify(jwk));
};

const readPrivateKey = async (kid: string, algo: KeyAlgo): Promise<CryptoKey | null> => {
  const raw = localStorage.getItem(PRIVKEY_PREFIX + kid);
  if (!raw) return null;
  const jwk = JSON.parse(raw);
  if (algo === "ECDSA_P256") {
    return crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign"]
    );
  }
  // RSA_PSS
  return crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSA-PSS", hash: "SHA-256" },
    true,
    ["sign"]
  );
};

// ------------------------------------------------------
// Crypto helpers (P-256 / RSA-PSS)
// ------------------------------------------------------

async function genKeyPair(algo: KeyAlgo): Promise<{ publicKey: CryptoKey; privateKey: CryptoKey; publicJwk: JsonWebKey }>{
  if (algo === "ECDSA_P256") {
    const kp = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    );
    const jwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
    return { publicKey: kp.publicKey, privateKey: kp.privateKey, publicJwk: jwk };
  }
  const kp = await crypto.subtle.generateKey(
    { name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([0x01, 0x00, 0x01]), hash: "SHA-256" },
    true,
    ["sign", "verify"]
  );
  const jwk = await crypto.subtle.exportKey("jwk", (kp as CryptoKeyPair).publicKey);
  return { publicKey: (kp as CryptoKeyPair).publicKey, privateKey: (kp as CryptoKeyPair).privateKey, publicJwk: jwk };
}

async function signBytes(algo: KeyAlgo, key: CryptoKey, data: Uint8Array): Promise<string> {
  const buffer = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer;
  if (algo === "ECDSA_P256") {
    const sig = await crypto.subtle.sign({ name: "ECDSA", hash: { name: "SHA-256" } }, key, buffer);
    return b64url(new Uint8Array(sig));
  }
  const sig = await crypto.subtle.sign({ name: "RSA-PSS", saltLength: 32 }, key, buffer);
  return b64url(new Uint8Array(sig));
}

async function verifyBytes(algo: KeyAlgo, pubKey: CryptoKey, data: Uint8Array, sigB64u: string): Promise<boolean> {
  const sig = fromB64url(sigB64u);
  const dataBuffer = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer;
  const sigBuffer = sig.buffer.slice(sig.byteOffset, sig.byteOffset + sig.byteLength) as ArrayBuffer;
  if (algo === "ECDSA_P256") {
    return crypto.subtle.verify({ name: "ECDSA", hash: { name: "SHA-256" } }, pubKey, sigBuffer, dataBuffer);
  }
  return crypto.subtle.verify({ name: "RSA-PSS", saltLength: 32 }, pubKey, sigBuffer, dataBuffer);
}

// ------------------------------------------------------
// DID helpers (simple deterministic did:key-like for demo)
// ------------------------------------------------------

const encoder = new TextEncoder();

function b64url(bytes: Uint8Array): string {
  const base64 = btoa(String.fromCharCode(...bytes));
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function fromB64url(s: string): Uint8Array {
  const base64 = s.replace(/-/g, "+").replace(/_/g, "/") + "==".slice((2 - (s.length * 3) % 4) % 4);
  const bin = atob(base64);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

function fingerprintFromJwk(jwk: JsonWebKey): string {
  // Minimal fingerprint: SHA-256 hash of canonical JWK
  const canon = JSON.stringify(jwk, Object.keys(jwk).sort());
  const bytes = encoder.encode(canon);
  // sync digest wrapper not available; using subtle.digest returns Promise
  // We'll expose an async wrapper from call sites.
  throw new Error("fingerprintFromJwk requires async; use asyncFingerprintFromJwk");
}

async function asyncFingerprintFromJwk(jwk: JsonWebKey): Promise<string> {
  const canon = JSON.stringify(jwk, Object.keys(jwk).sort());
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(canon));
  return b64url(new Uint8Array(digest));
}

async function buildDid(method: DidMethod, jwk: JsonWebKey): Promise<{ did: string; kid: string }>{
  const fp = await asyncFingerprintFromJwk(jwk);
  if (method === "did:web") {
    // Placeholder host; в реальном проекте подставлять домен.
    return { did: `did:web:example.com:${fp}`, kid: `#keys-1` };
  }
  if (method === "did:key") {
    return { did: `did:key:${fp}`, kid: `#${fp.slice(0, 16)}` };
  }
  return { did: `did:example:${fp}`, kid: `#${fp.slice(0, 16)}` };
}

function docFromRecord(rec: DidRecord): DidDocument {
  const vmId = `${rec.id}${rec.kid}`;
  const type = rec.algo === "ECDSA_P256" ? "JsonWebKey2020" : "RsaVerificationKey2018";
  return {
    id: rec.id,
    controller: rec.controller,
    verificationMethod: [
      {
        id: vmId,
        type,
        controller: rec.controller,
        publicKeyJwk: rec.publicKeyJwk,
      },
    ],
    authentication: [vmId],
    assertionMethod: [vmId],
  };
}

// ------------------------------------------------------
// Main Component
// ------------------------------------------------------

export default function DIDManager() {
  const { toast } = useToast();
  const [records, setRecords] = useState<DidRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [createOpen, setCreateOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [inspect, setInspect] = useState<DidRecord | null>(null);

  const [algo, setAlgo] = useState<KeyAlgo>("ECDSA_P256");
  const [method, setMethod] = useState<DidMethod>("did:key");

  const [signMsg, setSignMsg] = useState("");
  const [signResult, setSignResult] = useState<string | null>(null);
  const [verifySig, setVerifySig] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    try {
      setLoading(true);
      const data = loadRecords();
      setRecords(data);
    } catch (e: any) {
      setError(e?.message ?? "Load error");
    } finally {
      setLoading(false);
    }
  }, []);

  const defaultDid = useMemo(() => records.find((r) => r.isDefault) ?? null, [records]);

  const refresh = () => {
    setRecords(loadRecords());
  };

  const createDid = async () => {
    setBusy(true);
    try {
      const { publicKey, privateKey, publicJwk } = await genKeyPair(algo);
      const { did, kid } = await buildDid(method, publicJwk);
      const now = Date.now();
      const rec: DidRecord = {
        id: did,
        method,
        createdAt: now,
        updatedAt: now,
        status: "active" as DidStatus,
        algo,
        controller: did,
        publicKeyJwk: publicJwk,
        kid,
        isDefault: records.length === 0,
      };
      const next = [...records, rec];
      persistRecords(next);
      await savePrivateKey(did + kid, privateKey);
      setRecords(next);
      setCreateOpen(false);
      toast({ title: "DID создан", description: did });
    } catch (e: any) {
      toast({ title: "Ошибка создания DID", description: String(e?.message ?? e), variant: "destructive" });
    } finally {
      setBusy(false);
    }
  };

  const importDid = async (json: string) => {
    setBusy(true);
    try {
      const parsed = JSON.parse(json) as DidRecord;
      if (!parsed?.id || !parsed?.publicKeyJwk || !parsed?.kid) throw new Error("Некорректный формат DIDRecord");
      const exists = records.some((r) => r.id === parsed.id);
      const next = exists ? records.map((r) => (r.id === parsed.id ? parsed : r)) : [...records, parsed];
      persistRecords(next);
      setRecords(next);
      setImportOpen(false);
      toast({ title: exists ? "DID обновлён" : "DID импортирован", description: parsed.id });
    } catch (e: any) {
      toast({ title: "Ошибка импорта", description: String(e?.message ?? e), variant: "destructive" });
    } finally {
      setBusy(false);
    }
  };

  const revokeDid = (id: string) => {
    const next = records.map((r) => (r.id === id ? { ...r, status: "revoked" as DidStatus, updatedAt: Date.now() } : r));
    persistRecords(next);
    setRecords(next);
    toast({ title: "DID отозван", description: id });
  };

  const rotateKey = async (id: string) => {
    setBusy(true);
    try {
      const rec = records.find((r) => r.id === id);
      if (!rec) throw new Error("DID не найден");
      const { publicKey, privateKey, publicJwk } = await genKeyPair(rec.algo);
      const fp = await asyncFingerprintFromJwk(publicJwk);
      const newKid = `#${fp.slice(0, 16)}`;
      const updated: DidRecord = {
        ...rec,
        publicKeyJwk: publicJwk,
        kid: newKid,
        updatedAt: Date.now(),
      };
      const next = records.map((r) => (r.id === id ? updated : r));
      persistRecords(next);
      await savePrivateKey(updated.id + updated.kid, privateKey);
      setRecords(next);
      toast({ title: "Ключи ротированы", description: id });
    } catch (e: any) {
      toast({ title: "Ошибка ротации", description: String(e?.message ?? e), variant: "destructive" });
    } finally {
      setBusy(false);
    }
  };

  const setDefault = (id: string) => {
    const next = records.map((r) => ({ ...r, isDefault: r.id === id }));
    persistRecords(next);
    setRecords(next);
    toast({ title: "DID по умолчанию", description: id });
  };

  const exportRecord = (rec: DidRecord) => {
    const blob = new Blob([JSON.stringify(rec, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${rec.id.replace(/[:]/g, "_")}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const copy = (s: string) => navigator.clipboard.writeText(s);

  const signDefault = async () => {
    try {
      if (!defaultDid) throw new Error("Не выбран DID по умолчанию");
      const priv = await readPrivateKey(defaultDid.id + defaultDid.kid, defaultDid.algo);
      if (!priv) throw new Error("Приватный ключ не найден для текущего DID");
      const sig = await signBytes(defaultDid.algo, priv, encoder.encode(signMsg));
      setSignResult(sig);
    } catch (e: any) {
      setSignResult(null);
      toast({ title: "Ошибка подписи", description: String(e?.message ?? e), variant: "destructive" });
    }
  };

  const verifyWith = async (rec: DidRecord, message: string, sig: string) => {
    try {
      const pub = await crypto.subtle.importKey(
        "jwk",
        rec.publicKeyJwk,
        rec.algo === "ECDSA_P256" ? { name: "ECDSA", namedCurve: "P-256" } : { name: "RSA-PSS", hash: "SHA-256" },
        true,
        ["verify"]
      );
      const ok = await verifyBytes(rec.algo, pub, encoder.encode(message), sig);
      toast({ title: ok ? "Подпись валидна" : "Подпись НЕвалидна", description: rec.id, variant: ok ? "default" : "destructive" });
    } catch (e: any) {
      toast({ title: "Ошибка проверки", description: String(e?.message ?? e), variant: "destructive" });
    }
  };

  // Derived
  const active = records.filter((r) => r.status === "active");

  return (
    <div className="p-6 md:p-8 space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-2xl md:text-3xl font-semibold tracking-tight">DID Manager</h1>
          <p className="text-sm text-muted-foreground">Управление децентрализованными идентификаторами: создание, ключи, документы, подпись</p>
        </div>
        <div className="flex items-center gap-2">
          <Dialog open={createOpen} onOpenChange={setCreateOpen}>
            <DialogTrigger asChild>
              <Button>
                <Plus className="h-4 w-4" />
                <span className="ml-2 hidden sm:inline">Создать DID</span>
              </Button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-[520px]">
              <DialogHeader>
                <DialogTitle>Создание DID</DialogTitle>
                <DialogDescription>Выберите метод и алгоритм ключей</DialogDescription>
              </DialogHeader>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 py-2">
                <div>
                  <Label>Метод</Label>
                  <Select value={method} onValueChange={(v) => setMethod(v as DidMethod)}>
                    <SelectTrigger className="mt-1"><SelectValue placeholder="Метод" /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="did:key">did:key</SelectItem>
                      <SelectItem value="did:web">did:web</SelectItem>
                      <SelectItem value="did:example">did:example</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label>Алгоритм</Label>
                  <Select value={algo} onValueChange={(v) => setAlgo(v as KeyAlgo)}>
                    <SelectTrigger className="mt-1"><SelectValue placeholder="Алгоритм" /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="ECDSA_P256">ECDSA P-256</SelectItem>
                      <SelectItem value="RSA_PSS">RSA-PSS 2048</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setCreateOpen(false)}>Отмена</Button>
                <Button onClick={createDid} disabled={busy}>{busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />}<span className="ml-2">Создать</span></Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>

          <Dialog open={importOpen} onOpenChange={setImportOpen}>
            <DialogTrigger asChild>
              <Button variant="outline">
                <FileJson className="h-4 w-4" />
                <span className="ml-2 hidden sm:inline">Импорт JSON</span>
              </Button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-[700px]">
              <DialogHeader>
                <DialogTitle>Импорт DID</DialogTitle>
                <DialogDescription>Вставьте JSON DidRecord</DialogDescription>
              </DialogHeader>
              <Textarea className="min-h-[220px]" id="import-json" />
              <DialogFooter>
                <Button variant="outline" onClick={() => setImportOpen(false)}>Отмена</Button>
                <Button onClick={() => {
                  const el = document.getElementById("import-json") as HTMLTextAreaElement | null;
                  if (!el) return;
                  importDid(el.value);
                }}>Импортировать</Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {/* Default DID + Sign */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-base">DID по умолчанию</CardTitle>
          <CardDescription>Используется для подписи сообщений</CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <Skeleton className="h-12 w-full" />
          ) : defaultDid ? (
            <div className="flex flex-col gap-3">
              <div className="flex items-center justify-between gap-2">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <Badge>{defaultDid.method}</Badge>
                    <span className="truncate font-medium">{defaultDid.id}</span>
                  </div>
                  <div className="text-xs text-muted-foreground">kid: {defaultDid.kid} • algo: {defaultDid.algo}</div>
                </div>
                <Button variant="outline" size="icon" onClick={() => copy(defaultDid.id)} aria-label="Копировать DID"><Copy className="h-4 w-4" /></Button>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
                <div className="md:col-span-4">
                  <Label>Сообщение</Label>
                  <Input value={signMsg} onChange={(e) => setSignMsg(e.target.value)} placeholder="Введите сообщение для подписи" />
                </div>
                <div className="flex items-end">
                  <Button className="w-full" onClick={signDefault} disabled={!signMsg}>
                    <KeyRound className="h-4 w-4" />
                    <span className="ml-2">Подписать</span>
                  </Button>
                </div>
              </div>

              {signResult && (
                <div className="rounded-md border p-3 bg-muted/30">
                  <div className="text-xs font-medium mb-1">Подпись (base64url)</div>
                  <div className="text-xs break-all">{signResult}</div>
                  <div className="mt-2 flex gap-2">
                    <Button variant="outline" size="sm" onClick={() => copy(signResult)}><Copy className="h-3 w-3" /><span className="ml-2">Копировать</span></Button>
                    <Button variant="outline" size="sm" onClick={() => setSignResult(null)}><RotateCcw className="h-3 w-3" /><span className="ml-2">Очистить</span></Button>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="text-sm text-muted-foreground">Нет выбранного DID. Создайте новый или пометьте существующий как по умолчанию.</div>
          )}
        </CardContent>
      </Card>

      {/* Records table */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-base">Список DID</CardTitle>
          <CardDescription>Активные и отозванные записи</CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <TableSkeleton />
          ) : (
            <div className="w-full overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Статус</TableHead>
                    <TableHead>DID</TableHead>
                    <TableHead>Метод</TableHead>
                    <TableHead>Алгоритм</TableHead>
                    <TableHead>Создан</TableHead>
                    <TableHead>Обновлён</TableHead>
                    <TableHead className="text-right">Действия</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {records.map((r) => (
                    <motion.tr key={r.id} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.2 }} className="border-b">
                      <TableCell>
                        <Badge variant={r.status === "active" ? "default" : "destructive"} className="capitalize">{r.status}</Badge>
                        {r.isDefault && <Badge variant="secondary" className="ml-2">default</Badge>}
                      </TableCell>
                      <TableCell className="max-w-[360px]">
                        <div className="flex items-center gap-2">
                          <Fingerprint className="h-4 w-4" />
                          <span className="truncate" title={r.id}>{r.id}</span>
                        </div>
                      </TableCell>
                      <TableCell>{r.method}</TableCell>
                      <TableCell>{r.algo}</TableCell>
                      <TableCell>{formatDate(r.createdAt, "yyyy-MM-dd HH:mm")}</TableCell>
                      <TableCell>{formatDate(r.updatedAt, "yyyy-MM-dd HH:mm")}</TableCell>
                      <TableCell className="text-right">
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="icon" aria-label="Меню"><MoreHorizontal className="h-4 w-4" /></Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuLabel>Действия</DropdownMenuLabel>
                            <DropdownMenuItem onClick={() => setInspect(r)}>
                              Показать документ
                              <DropdownMenuShortcut><LinkIcon className="h-3 w-3" /></DropdownMenuShortcut>
                            </DropdownMenuItem>
                            <DropdownMenuItem onClick={() => exportRecord(r)}>
                              Экспорт JSON
                              <DropdownMenuShortcut><Download className="h-3 w-3" /></DropdownMenuShortcut>
                            </DropdownMenuItem>
                            <DropdownMenuItem onClick={() => copy(r.id)}>
                              Копировать DID
                              <DropdownMenuShortcut><Copy className="h-3 w-3" /></DropdownMenuShortcut>
                            </DropdownMenuItem>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem onClick={() => setDefault(r.id)}>
                              Сделать по умолчанию
                              <DropdownMenuShortcut><ShieldCheck className="h-3 w-3" /></DropdownMenuShortcut>
                            </DropdownMenuItem>
                            <DropdownMenuItem onClick={() => rotateKey(r.id)}>
                              Ротация ключей
                              <DropdownMenuShortcut><RefreshCw className="h-3 w-3" /></DropdownMenuShortcut>
                            </DropdownMenuItem>
                            <DropdownMenuItem onClick={() => verifyWith(r, signMsg, verifySig)} disabled={!verifySig || !signMsg}>
                              Проверить подпись
                              <DropdownMenuShortcut><Check className="h-3 w-3" /></DropdownMenuShortcut>
                            </DropdownMenuItem>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem className="text-destructive focus:text-destructive" onClick={() => revokeDid(r.id)}>
                              Отозвать
                              <DropdownMenuShortcut><Trash2 className="h-3 w-3" /></DropdownMenuShortcut>
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </TableCell>
                    </motion.tr>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}

          {/* Verify panel */}
          <div className="mt-6 grid grid-cols-1 md:grid-cols-3 gap-3">
            <div className="md:col-span-2">
              <Label>Сообщение для проверки</Label>
              <Input value={signMsg} onChange={(e) => setSignMsg(e.target.value)} placeholder="Сообщение" />
            </div>
            <div>
              <Label>Подпись (base64url)</Label>
              <Input value={verifySig} onChange={(e) => setVerifySig(e.target.value)} placeholder="Подпись" />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Inspect dialog */}
      <Dialog open={!!inspect} onOpenChange={(o) => !o && setInspect(null)}>
        <DialogContent className="max-w-3xl">
          <DialogHeader>
            <DialogTitle>DID Document</DialogTitle>
            <DialogDescription>Верификационные методы и контроллер</DialogDescription>
          </DialogHeader>
          {inspect ? (
            <div className="space-y-3">
              <pre className="text-xs p-3 rounded-md bg-muted overflow-auto max-h-[420px]">{JSON.stringify(docFromRecord(inspect), null, 2)}</pre>
              <div className="flex justify-end gap-2">
                <Button variant="outline" onClick={() => navigator.clipboard.writeText(JSON.stringify(docFromRecord(inspect), null, 2))}><Copy className="h-4 w-4" /><span className="ml-2">Копировать JSON</span></Button>
                <Button onClick={() => exportRecord(inspect)}><Download className="h-4 w-4" /><span className="ml-2">Экспорт</span></Button>
              </div>
            </div>
          ) : null}
        </DialogContent>
      </Dialog>

      {/* Footnote */}
      <div className="text-xs text-muted-foreground">
        <div className="flex items-center gap-2"><ShieldAlert className="h-3.5 w-3.5" />Реализация ключей использует WebCrypto (ECDSA P-256, RSA-PSS). Для иных методов/алгоритмов подключайте провайдеры DID на бэкенде.</div>
      </div>
    </div>
  );
}

function TableSkeleton() {
  return (
    <div className="space-y-2">
      {Array.from({ length: 6 }).map((_, i) => (
        <Skeleton key={i} className="h-10 w-full" />
      ))}
    </div>
  );
}
