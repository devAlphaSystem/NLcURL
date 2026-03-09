/**
 * SSE client with automatic reconnection and Last-Event-ID tracking
 * per the WHATWG EventSource specification.
 * https://html.spec.whatwg.org/multipage/server-sent-events.html
 */
import { EventEmitter } from "node:events";
import type { ServerSentEvent } from "../core/request.js";
import { SSEParser } from "./parser.js";

/** Configuration for the SSE client. */
export interface SSEClientOptions {
  /** Additional headers to send with the request. */
  headers?: Record<string, string>;
  /** Initial retry delay in milliseconds (default: 3000). */
  retryMs?: number;
  /** Maximum number of reconnection attempts (default: Infinity). */
  maxRetries?: number;
  /** A function that performs the actual HTTP request, returning a readable stream. */
  fetch: (url: string, headers: Record<string, string>) => Promise<SSEFetchResult>;
}

export interface SSEFetchResult {
  status: number;
  headers: Record<string, string>;
  body: AsyncIterable<Buffer | string>;
}

/** Event map for {@link SSEClient}. */
export interface SSEClientEvents {
  event: [event: ServerSentEvent];
  open: [];
  error: [error: Error];
  close: [];
}

export type SSEClientState = "connecting" | "open" | "closed";

/**
 * Server-Sent Events client with automatic reconnection.
 *
 * Implements WHATWG EventSource behavior: reconnects on network errors,
 * sends Last-Event-ID header, respects retry field from server.
 */
export class SSEClient extends EventEmitter {
  public state: SSEClientState = "connecting";
  public readonly url: string;

  private lastEventId = "";
  private retryMs: number;
  private maxRetries: number;
  private retryCount = 0;
  private headers: Record<string, string>;
  private fetchFn: SSEClientOptions["fetch"];
  private aborted = false;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(url: string, options: SSEClientOptions) {
    super();
    this.url = url;
    this.retryMs = options.retryMs ?? 3000;
    this.maxRetries = options.maxRetries ?? Infinity;
    this.headers = options.headers ?? {};
    this.fetchFn = options.fetch;
    this.connect();
  }

  /** Close the SSE connection and stop reconnecting. */
  close(): void {
    this.aborted = true;
    this.state = "closed";
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.emit("close");
  }

  private async connect(): Promise<void> {
    if (this.aborted) return;

    const reqHeaders: Record<string, string> = {
      ...this.headers,
      accept: "text/event-stream",
      "cache-control": "no-cache",
    };
    if (this.lastEventId) {
      reqHeaders["last-event-id"] = this.lastEventId;
    }

    try {
      const result = await this.fetchFn(this.url, reqHeaders);

      if (result.status !== 200) {
        const err = new Error(`SSE connection failed with status ${result.status}`);
        this.emit("error", err);
        if (result.status >= 400 && result.status < 500 && result.status !== 408 && result.status !== 429) {
          this.state = "closed";
          this.emit("close");
          return;
        }
        this.scheduleReconnect();
        return;
      }

      this.state = "open";
      this.retryCount = 0;
      this.emit("open");

      const parser = new SSEParser();

      for await (const chunk of result.body) {
        if (this.aborted) return;
        const text = typeof chunk === "string" ? chunk : (chunk as Buffer).toString("utf8");
        parser.feed(text);

        let event: ServerSentEvent | null;
        while ((event = parser.pull()) !== null) {
          if (event.id) this.lastEventId = event.id;
          if (event.retry !== undefined) this.retryMs = event.retry;
          this.emit("event", event);
        }
      }

      parser.flush();
      let event: ServerSentEvent | null;
      while ((event = parser.pull()) !== null) {
        if (event.id) this.lastEventId = event.id;
        this.emit("event", event);
      }

      if (!this.aborted) {
        this.scheduleReconnect();
      }
    } catch (err) {
      if (this.aborted) return;
      this.emit("error", err instanceof Error ? err : new Error(String(err)));
      this.scheduleReconnect();
    }
  }

  private scheduleReconnect(): void {
    if (this.aborted) return;
    this.retryCount++;
    if (this.retryCount > this.maxRetries) {
      this.state = "closed";
      this.emit("close");
      return;
    }
    this.state = "connecting";
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, this.retryMs);
  }
}
