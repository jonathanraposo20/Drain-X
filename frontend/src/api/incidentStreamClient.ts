import {
  IncidentStreamEvent,
  IncidentStreamInitMessage,
  StreamConnectionStatus,
} from '../types/contracts';

export interface IncidentStreamClientOptions {
  url?: string;
  token?: string | null;
  baseReconnectDelayMs?: number;
  maxReconnectDelayMs?: number;
  reconnectFactor?: number;
  maxReconnectAttempts?: number;
  heartbeatIntervalMs?: number;
  onInit?: (msg: IncidentStreamInitMessage) => void;
  onEvent?: (event: IncidentStreamEvent) => void;
  onResyncRequired?: (reason?: string | null) => void;
  onStatusChange?: (status: StreamConnectionStatus, detail?: string) => void;
  onError?: (err: string | Event) => void;
}

export function getIncidentWebSocketStreamUrl(
  path: string = '/api/v1/incidents/stream',
  token?: string | null,
  lastSeqId?: number | null,
  lastInstanceId?: string | null
): string {
  const configuredWsBase =
    typeof import.meta !== 'undefined' && import.meta.env
      ? (import.meta.env.VITE_WS_BASE_URL as string | undefined)
      : undefined;

  let base = 'ws://127.0.0.1:8000';
  if (configuredWsBase) {
    base = configuredWsBase.replace(/\/+$/, '');
  } else if (typeof window !== 'undefined' && window.location) {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host || '127.0.0.1:8000';
    base = `${protocol}//${host}`;
  }

  const url = new URL(`${base}${path.startsWith('/') ? path : '/' + path}`);
  if (token) url.searchParams.set('token', token);
  if (lastSeqId !== undefined && lastSeqId !== null) {
    url.searchParams.set('last_seq_id', String(lastSeqId));
  }
  if (lastInstanceId) {
    url.searchParams.set('last_instance_id', lastInstanceId);
  }
  return url.toString();
}

export class IncidentStreamClient {
  private ws: WebSocket | null = null;
  private status: StreamConnectionStatus = 'DISCONNECTED';
  private reconnectAttempts = 0;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private isExplicitlyClosed = false;

  private lastSeqId: number | null = null;
  private instanceId: string | null = null;

  private options: IncidentStreamClientOptions;

  constructor(options: IncidentStreamClientOptions = {}) {
    this.options = {
      baseReconnectDelayMs: 1000,
      maxReconnectDelayMs: 8000,
      reconnectFactor: 1.5,
      maxReconnectAttempts: 10,
      heartbeatIntervalMs: 15000,
      ...options,
    };
  }

  public getStatus(): StreamConnectionStatus {
    return this.status;
  }

  public isConnected(): boolean {
    return this.status === 'CONNECTED';
  }

  public getLastSeqId(): number | null {
    return this.lastSeqId;
  }

  public getInstanceId(): string | null {
    return this.instanceId;
  }

  public setToken(token: string | null): void {
    const tokenChanged = this.options.token !== token;
    this.options.token = token;
    if (tokenChanged && this.ws && this.status === 'CONNECTED') {
      this.reconnect();
    }
  }

  public connect(): void {
    if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) {
      return;
    }

    this.isExplicitlyClosed = false;
    this.clearTimers();

    const url =
      this.options.url ||
      getIncidentWebSocketStreamUrl(
        '/api/v1/incidents/stream',
        this.options.token,
        this.lastSeqId,
        this.instanceId
      );

    try {
      this.ws = new WebSocket(url);
    } catch (err) {
      this.handleConnectionFailure(`Failed to create WebSocket: ${err instanceof Error ? err.message : String(err)}`);
      return;
    }

    this.ws.onopen = this.handleOpen.bind(this);
    this.ws.onmessage = this.handleMessage.bind(this);
    this.ws.onerror = this.handleError.bind(this);
    this.ws.onclose = this.handleClose.bind(this);
  }

  public disconnect(): void {
    this.isExplicitlyClosed = true;
    this.clearTimers();
    if (this.ws) {
      this.ws.onopen = null;
      this.ws.onmessage = null;
      this.ws.onerror = null;
      this.ws.onclose = null;
      try {
        this.ws.close(1000, 'Client unmounted');
      } catch {
        // Ignored
      }
      this.ws = null;
    }
    this.updateStatus('DISCONNECTED', 'Connection closed by client');
  }

  public ping(): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      try {
        this.ws.send(JSON.stringify({ action: 'ping' }));
      } catch {
        // Ignored
      }
    }
  }

  private handleOpen(): void {
    this.reconnectAttempts = 0;
    this.updateStatus('CONNECTED', 'Incident WebSocket stream connected');
    this.startHeartbeat();
  }

  private handleMessage(event: MessageEvent): void {
    try {
      const data = JSON.parse(event.data as string);

      if (data.event_type === 'INIT') {
        const initMsg = data as IncidentStreamInitMessage;
        this.instanceId = initMsg.instance_id;
        if (this.lastSeqId === null || this.lastSeqId === undefined) {
          this.lastSeqId = initMsg.current_seq_id;
        }
        if (this.options.onInit) {
          this.options.onInit(initMsg);
        }
        return;
      }

      if (data.event_type === 'PONG') {
        return;
      }

      if (data.event_type === 'HEARTBEAT') {
        if (typeof data.seq_id === 'number') {
          this.lastSeqId = Math.max(this.lastSeqId ?? 0, data.seq_id);
        }
        return;
      }

      if (data.event_type === 'RESYNC_REQUIRED') {
        if (data.instance_id) {
          this.instanceId = data.instance_id;
        }
        if (typeof data.seq_id === 'number') {
          this.lastSeqId = data.seq_id;
        }
        if (this.options.onResyncRequired) {
          this.options.onResyncRequired(data.reason);
        }
        return;
      }

      // Operational incident events
      const incEvent = data as IncidentStreamEvent;
      if (typeof incEvent.seq_id === 'number') {
        this.lastSeqId = incEvent.seq_id;
      }
      if (incEvent.instance_id) {
        this.instanceId = incEvent.instance_id;
      }

      if (this.options.onEvent) {
        this.options.onEvent(incEvent);
      }
    } catch (err) {
      if (this.options.onError) {
        this.options.onError(`Failed to parse incident stream frame: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
  }

  private handleError(event: Event): void {
    if (this.options.onError) {
      this.options.onError(event);
    }
  }

  private handleClose(event: CloseEvent): void {
    this.clearTimers();
    this.ws = null;

    if (this.isExplicitlyClosed) {
      this.updateStatus('DISCONNECTED', 'Connection closed normally');
      return;
    }

    // Code 1008 is Policy Violation (e.g. Unauthorized or Stalled Consumer)
    if (event.code === 1008) {
      this.updateStatus('DISCONNECTED', `Disconnected due to policy violation: ${event.reason || 'Unauthorized'}`);
      return;
    }

    this.handleConnectionFailure(`WebSocket closed (code=${event.code}, reason=${event.reason || 'None'})`);
  }

  private handleConnectionFailure(reason: string): void {
    const maxAttempts = this.options.maxReconnectAttempts ?? 10;
    if (this.reconnectAttempts >= maxAttempts) {
      this.updateStatus('DISCONNECTED', `Max reconnect attempts (${maxAttempts}) reached. Stream offline.`);
      return;
    }

    this.reconnectAttempts += 1;
    this.updateStatus('RECONNECTING', `Attempt ${this.reconnectAttempts}/${maxAttempts}: ${reason}`);

    const baseDelay = this.options.baseReconnectDelayMs ?? 1000;
    const maxDelay = this.options.maxReconnectDelayMs ?? 8000;
    const factor = this.options.reconnectFactor ?? 1.5;

    const exponentialDelay = Math.min(baseDelay * Math.pow(factor, this.reconnectAttempts - 1), maxDelay);
    const jitter = Math.random() * 500;
    const delay = exponentialDelay + jitter;

    this.reconnectTimer = setTimeout(() => {
      this.connect();
    }, delay);
  }

  private reconnect(): void {
    this.disconnect();
    this.connect();
  }

  private updateStatus(status: StreamConnectionStatus, detail?: string): void {
    this.status = status;
    if (this.options.onStatusChange) {
      this.options.onStatusChange(status, detail);
    }
  }

  private startHeartbeat(): void {
    const interval = this.options.heartbeatIntervalMs ?? 15000;
    this.heartbeatTimer = setInterval(() => {
      this.ping();
    }, interval);
  }

  private clearTimers(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }
}
