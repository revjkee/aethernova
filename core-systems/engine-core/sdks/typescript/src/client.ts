/* eslint-disable no-console */
import WebSocket from 'isomorphic-ws';
import { z } from 'zod';

// ------------------------------------------------------
// Типы протокола и вспомогательные сущности
// ------------------------------------------------------
export type Millis = number;

export enum AuthMode {
  Header = 'header',        // Только для Node (можно передать headers)
  Query = 'query',          // ?token=...
  Subprotocol = 'subproto', // Bearer <token> через Sec-WebSocket-Protocol
  None = 'none'
}

export type TokenProvider = () => Promise<string | null> | string | null;

export interface EngineWSClientOptions {
  url: string;
  getToken?: TokenProvider;
  authMode?: AuthMode;
  /**
   * Максимальная длительность попытки RPC/ответа.
   */
  rpcTimeout?: Millis;
  /**
   * Период пинга соединения.
   */
  heartbeatInterval?: Millis;
  /**
   * Таймаут ожидания pong.
   */
  heartbeatTimeout?: Millis;
  /**
   * Backoff: начальная задержка (мс).
   */
  reconnectBackoffMin?: Millis;
  /**
   * Backoff: максимальная задержка (мс).
   */
  reconnectBackoffMax?: Millis;
  /**
   * Лимит попыток переподключения; Infinity для неограниченных.
   */
  reconnectAttempts?: number;
  /**
   * Максимальный размер очереди оффлайн‑сообщений.
   */
  offlineQueueLimit?: number;
  /**
   * Кастомные заголовки (используются только в Node среде).
   */
  headers?: Record<string, string>;
  /**
   * Пользовательский логгер.
   */
  logger?: Pick<Console, 'info' | 'warn' | 'error' | 'debug'>;
}

// Сообщение протокола
const EnvelopeSchema = z.object({
  id: z.string().optional(),       // соотнесение запроса и ответа
  t: z.string(),                   // тип сообщения/события
  ts: z.number().optional(),       // серверная метка времени
  ok: z.boolean().optional(),      // статус RPC
  err: z
    .object({
      code: z.string(),
      message: z.string(),
      details: z.unknown().optional()
    })
    .optional(),
  meta: z.record(z.unknown()).optional(),
  data: z.unknown().optional()
});
export type Envelope = z.infer<typeof EnvelopeSchema>;

// Встроенные типы событий
export const EventTypes = {
  Hello: 'sys.hello',
  Pong: 'sys.pong',
  Ping: 'sys.ping',
  Ack: 'sys.ack',
  Error: 'sys.error'
} as const;

// ------------------------------------------------------
// Утилиты
// ------------------------------------------------------
const defaultLogger: Required<EngineWSClientOptions>['logger'] = {
  info: console.log,
  warn: console.warn,
  error: console.error,
  debug: console.debug
};

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function now() {
  return Date.now();
}

function randJitter(share = 0.2) {
  // +/- 20% по умолчанию
  return 1 + (Math.random() * 2 - 1) * share;
}

function uid(): string {
  // криптографически стойкий, если есть Web Crypto
  if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) {
    return crypto.randomUUID();
  }
  // fallback
  return (
    Math.random().toString(36).slice(2) +
    Math.random().toString(36).slice(2) +
    Date.now().toString(36)
  );
}

function isNodeEnv(): boolean {
  return (
    typeof process !== 'undefined' &&
    process.versions != null &&
    (process.versions as any).node != null
  );
}

// ------------------------------------------------------
// Мини‑шина событий
// ------------------------------------------------------
type Handler = (e: Envelope) => void;
export class Emitter {
  private map = new Map<string, Set<Handler>>();

  on(type: string, fn: Handler) {
    if (!this.map.has(type)) this.map.set(type, new Set());
    this.map.get(type)!.add(fn);
  }

  off(type: string, fn: Handler) {
    this.map.get(type)?.delete(fn);
  }

  emit(type: string, e: Envelope) {
    this.map.get(type)?.forEach((fn) => {
      try {
        fn(e);
      } catch (err) {
        // eslint-disable-next-line no-console
        console.error('Emitter handler error', err);
      }
    });
    // wildcard
    this.map.get('*')?.forEach((fn) => {
      try {
        fn(e);
      } catch (err) {
        console.error('Emitter handler error', err);
      }
    });
  }
}

// ------------------------------------------------------
// Основной клиент
// ------------------------------------------------------
export class EngineWSClient {
  private options: Required<EngineWSClientOptions>;
  private ws: WebSocket | null = null;
  private connecting = false;
  private closedByUser = false;

  private reconnectTry = 0;
  private lastPongAt = 0;
  private heartbeatTimer: any = null;
  private heartbeatWaitTimer: any = null;

  private inflight = new Map<
    string,
    { resolve: (v: Envelope) => void; reject: (e: Error) => void; deadline: number }
  >();

  private offlineQueue: Envelope[] = [];
  private emitter = new Emitter();

  constructor(opts: EngineWSClientOptions) {
    if (!opts.url) throw new Error('url is required');

    this.options = {
      authMode: AuthMode.Query,
      rpcTimeout: 15_000,
      heartbeatInterval: 20_000,
      heartbeatTimeout: 10_000,
      reconnectBackoffMin: 500,
      reconnectBackoffMax: 20_000,
      reconnectAttempts: Infinity,
      offlineQueueLimit: 5_000,
      headers: {},
      logger: defaultLogger,
      getToken: async () => null,
      ...opts
    };
  }

  // ----------------------------
  // Общественный API
  // ----------------------------
  on(type: string, fn: Handler) {
    this.emitter.on(type, fn);
  }

  off(type: string, fn: Handler) {
    this.emitter.off(type, fn);
  }

  async connect(): Promise<void> {
    this.closedByUser = false;
    await this.openSocket();
  }

  async close(code = 1000, reason = 'client_close'): Promise<void> {
    this.closedByUser = true;
    this.stopHeartbeat();
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.close(code, reason);
    }
    this.ws = null;
  }

  /**
   * Отправка события/сообщения без ожидания ответа.
   */
  async send(type: string, data?: unknown, meta?: Record<string, unknown>): Promise<void> {
    const env: Envelope = { t: type, data, meta };
    await this.sendRaw(env);
  }

  /**
   * RPC с ожиданием ответа ok/err.
   */
  async rpc<TReq = unknown, TRes = unknown>(
    type: string,
    data?: TReq,
    opts?: { timeout?: Millis; meta?: Record<string, unknown> }
  ): Promise<Envelope & { data?: TRes }> {
    const id = uid();
    const deadline = now() + (opts?.timeout ?? this.options.rpcTimeout);
    const env: Envelope = { id, t: type, data, meta: opts?.meta };

    const promise = new Promise<Envelope>((resolve, reject) => {
      this.inflight.set(id, { resolve, reject, deadline });
    });

    await this.sendRaw(env);
    const res = await promise;
    if (res.ok === false || res.err) {
      const err = new Error(res.err?.message ?? 'RPC error');
      (err as any).code = res.err?.code;
      (err as any).details = res.err?.details;
      throw err;
    }
    return res as any;
  }

  /**
   * Горячая замена способа получения токена.
   */
  setTokenProvider(getToken: TokenProvider) {
    this.options.getToken = getToken;
  }

  // ------------------------------------------------------
  // Внутренняя логика
  // ------------------------------------------------------
  private buildUrlWithAuth(base: string, token: string | null): { url: string; protocols?: string[]; headers?: Record<string, string> } {
    const { authMode } = this.options;
    const headers: Record<string, string> = { ...(this.options.headers || {}) };
    const protocols: string[] = [];
    let url = base;

    if (authMode === AuthMode.None || !token) {
      return { url, protocols: protocols.length ? protocols : undefined, headers: Object.keys(headers).length ? headers : undefined };
    }

    if (authMode === AuthMode.Query) {
      const u = new URL(url);
      u.searchParams.set('token', token);
      url = u.toString();
    } else if (authMode === AuthMode.Subprotocol) {
      // Используем подпротокол Bearer.<base64 token> чтобы избежать пробелов
      const sub = `bearer.${Buffer.from(token).toString('base64url')}`;
      protocols.push(sub);
    } else if (authMode === AuthMode.Header) {
      if (!isNodeEnv()) {
        this.options.logger.warn('AuthMode.Header недоступен в браузере; переключитесь на Query/Subprotocol');
      } else {
        headers.Authorization = `Bearer ${token}`;
      }
    }
    return { url, protocols: protocols.length ? protocols : undefined, headers: Object.keys(headers).length ? headers : undefined };
  }

  private async openSocket(): Promise<void> {
    if (this.connecting || (this.ws && this.ws.readyState === WebSocket.OPEN)) return;

    this.connecting = true;
    const token = await Promise.resolve(this.options.getToken?.());
    const { url, protocols, headers } = this.buildUrlWithAuth(this.options.url, token);

    try {
      this.ws = new WebSocket(url, protocols as any, isNodeEnv() ? { headers } : undefined);
    } catch (err) {
      this.connecting = false;
      this.options.logger.error('WebSocket create error', err as any);
      await this.scheduleReconnect();
      return;
    }

    this.ws.onopen = () => {
      this.options.logger.info('WebSocket connected');
      this.connecting = false;
      this.reconnectTry = 0;
      this.startHeartbeat();
      this.flushOfflineQueue();
      // Приветствие
      this.safeSend({ t: EventTypes.Hello, meta: { sdk: 'ts', ver: '1.0.0' } });
    };

    this.ws.onmessage = (evt) => {
      try {
        const raw = typeof evt.data === 'string' ? evt.data : evt.data?.toString?.() ?? '';
        const parsed = EnvelopeSchema.safeParse(JSON.parse(raw));
        if (!parsed.success) {
          this.options.logger.warn('Invalid envelope', parsed.error);
          return;
        }
        const msg = parsed.data;

        // Обработка pong
        if (msg.t === EventTypes.Pong) {
          this.lastPongAt = now();
          return;
        }

        // Разрешение inflight по id
        if (msg.id && this.inflight.has(msg.id)) {
          const pending = this.inflight.get(msg.id)!;
          this.inflight.delete(msg.id);
          pending.resolve(msg);
          return;
        }

        // Маршрутизация событий
        this.emitter.emit(msg.t, msg);
        this.emitter.emit('*', msg);
      } catch (err) {
        this.options.logger.error('onmessage error', err as any);
      }
    };

    this.ws.onerror = (evt) => {
      this.options.logger.error('WebSocket error', evt);
    };

    this.ws.onclose = async (evt) => {
      this.options.logger.warn(`WebSocket closed code=${evt.code} reason=${evt.reason}`);
      this.stopHeartbeat();
      this.rejectAllInflight(new Error(`socket_closed_${evt.code}`));
      if (!this.closedByUser) {
        await this.scheduleReconnect();
      }
    };
  }

  private async scheduleReconnect() {
    if (this.closedByUser) return;

    const { reconnectAttempts, reconnectBackoffMin, reconnectBackoffMax } = this.options;
    if (this.reconnectTry >= (Number.isFinite(reconnectAttempts) ? (reconnectAttempts as number) : Number.POSITIVE_INFINITY)) {
      this.options.logger.error('Reconnect attempts exhausted');
      return;
    }

    const base = Math.min(
      reconnectBackoffMax,
      reconnectBackoffMin * Math.pow(2, this.reconnectTry)
    );
    const delay = Math.floor(base * randJitter());
    this.reconnectTry += 1;

    this.options.logger.info(`Reconnecting in ~${delay}ms (try #${this.reconnectTry})`);
    await sleep(delay);
    await this.openSocket();
  }

  private startHeartbeat() {
    this.stopHeartbeat();
    this.lastPongAt = now();

    this.heartbeatTimer = setInterval(() => {
      if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;
      this.safeSend({ t: EventTypes.Ping, ts: now() });

      // ожидание pong
      if (this.heartbeatWaitTimer) clearTimeout(this.heartbeatWaitTimer);
      this.heartbeatWaitTimer = setTimeout(() => {
        const since = now() - this.lastPongAt;
        if (since > (this.options.heartbeatTimeout ?? 10_000)) {
          this.options.logger.warn('Heartbeat timeout, closing socket');
          try {
            this.ws?.close(4001, 'heartbeat_timeout');
          } catch {}
        }
      }, this.options.heartbeatTimeout);
    }, this.options.heartbeatInterval);
  }

  private stopHeartbeat() {
    if (this.heartbeatTimer) clearInterval(this.heartbeatTimer);
    if (this.heartbeatWaitTimer) clearTimeout(this.heartbeatWaitTimer);
    this.heartbeatTimer = null;
    this.heartbeatWaitTimer = null;
  }

  private rejectAllInflight(err: Error) {
    for (const [, p] of this.inflight) {
      p.reject(err);
    }
    this.inflight.clear();
  }

  private async sendRaw(env: Envelope): Promise<void> {
    // Таймаут контроля inflight RPC
    if (env.id) {
      const p = this.inflight.get(env.id);
      if (p) {
        // сторожевой таймер
        const remain = p.deadline - now();
        if (remain <= 0) {
          this.inflight.delete(env.id);
          p.reject(new Error('rpc_timeout'));
          return;
        }
        setTimeout(() => {
          const pending = this.inflight.get(env.id);
          if (!pending) return;
          if (pending.deadline <= now()) {
            this.inflight.delete(env.id);
            pending.reject(new Error('rpc_timeout'));
          }
        }, Math.min(1_000, Math.max(1, remain)));
      }
    }

    // Если нет соединения — складываем в очередь
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      if (this.offlineQueue.length >= this.options.offlineQueueLimit) {
        this.offlineQueue.shift();
      }
      this.offlineQueue.push(env);
      if (!this.connecting && !this.closedByUser) {
        void this.openSocket();
      }
      return;
    }

    this.safeSend(env);
  }

  private safeSend(env: Envelope) {
    try {
      this.ws?.send(JSON.stringify(env));
    } catch (err) {
      this.options.logger.error('send error', err as any);
      // Вернём в очередь на повтор
      if (this.offlineQueue.length >= this.options.offlineQueueLimit) this.offlineQueue.shift();
      this.offlineQueue.push(env);
    }
  }

  private flushOfflineQueue() {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;
    while (this.offlineQueue.length) {
      const msg = this.offlineQueue.shift()!;
      this.safeSend(msg);
    }
  }
}

// ------------------------------------------------------
// Пример типобезопасной подписки (для справки использования)
// ------------------------------------------------------
// const client = new EngineWSClient({
//   url: 'wss://api.example.com/ws',
//   getToken: async () => 'YOUR_TOKEN',
//   authMode: isNodeEnv() ? AuthMode.Header : AuthMode.Subprotocol
// });
// client.on('*', (e) => console.log('event', e.t, e.data));
// await client.connect();
// await client.send('topic.subscribe', { topic: 'orders' });
// const res = await client.rpc('orders.get', { id: '123' });
