/**
 * Server-Sent Events (SSE) parser following the W3C EventSource specification.
 *
 * Provides both a streaming `SSEParser` class for incremental parsing and a
 * convenience `parseSSEStream()` async generator for consuming a `Readable`
 * stream of SSE events.
 *
 * @see https://html.spec.whatwg.org/multipage/server-sent-events.html#event-stream-interpretation
 */
import type { Readable } from "node:stream";
import type { ServerSentEvent } from "../core/request.js";

/**
 * Incremental SSE event parser. Feed raw bytes/text via {@link SSEParser.feed}
 * and retrieve complete events via {@link SSEParser.pull}.
 *
 * Follows the W3C algorithm: events are delimited by blank lines, fields are
 * prefixed by `event:`, `data:`, `id:`, or `retry:`. Lines beginning with `:`
 * are treated as comments and ignored. Unknown fields are ignored.
 */
export class SSEParser {
  /** Maximum allowed length for a single buffered line (64 KB). */
  private static readonly MAX_LINE_LENGTH = 65_536;
  /** Maximum allowed total size of accumulated data lines per event (1 MB). */
  private static readonly MAX_EVENT_SIZE = 1_048_576;

  private buffer = "";
  private eventType = "";
  private dataLines: string[] = [];
  private dataSize = 0;
  private lastEventId = "";
  private retry: number | undefined = undefined;
  private readonly events: ServerSentEvent[] = [];

  /**
   * Feeds raw text from the SSE stream into the parser. Call this each time
   * a chunk of data is received. Complete events are buffered internally
   * and retrieved via {@link pull}.
   *
   * @param {string} text - Raw text chunk from the event stream.
   */
  feed(text: string): void {
    this.buffer += text;

    if (this.buffer.length > SSEParser.MAX_LINE_LENGTH) {
      throw new Error(`SSE line exceeds maximum length of ${SSEParser.MAX_LINE_LENGTH} bytes`);
    }

    const lines = this.buffer.split(/\r\n|\r|\n/);
    this.buffer = lines.pop()!;

    for (const line of lines) {
      this.processLine(line);
    }
  }

  /**
   * Retrieves and removes the next complete SSE event from the internal
   * queue. Returns `null` when no complete events are available.
   *
   * @returns {ServerSentEvent | null}
   */
  pull(): ServerSentEvent | null {
    return this.events.shift() ?? null;
  }

  /**
   * Flushes the parser, processing any remaining incomplete buffer as if
   * the stream ended. Call after the stream closes to emit any pending event.
   */
  flush(): void {
    if (this.buffer.length > 0) {
      this.processLine(this.buffer);
      this.buffer = "";
    }
    this.dispatchEvent();
  }

  private processLine(line: string): void {
    if (line === "") {
      this.dispatchEvent();
      return;
    }

    if (line.startsWith(":")) return;

    const colonIdx = line.indexOf(":");
    let field: string;
    let value: string;

    if (colonIdx === -1) {
      field = line;
      value = "";
    } else {
      field = line.substring(0, colonIdx);
      value = line.substring(colonIdx + 1);
      if (value.startsWith(" ")) {
        value = value.substring(1);
      }
    }

    switch (field) {
      case "event":
        this.eventType = value;
        break;
      case "data":
        this.dataSize += value.length + 1;
        if (this.dataSize > SSEParser.MAX_EVENT_SIZE) {
          throw new Error(`SSE event data exceeds maximum size of ${SSEParser.MAX_EVENT_SIZE} bytes`);
        }
        this.dataLines.push(value);
        break;
      case "id":
        if (!value.includes("\0")) {
          this.lastEventId = value;
        }
        break;
      case "retry": {
        const parsed = parseInt(value, 10);
        if (!Number.isNaN(parsed) && parsed >= 0 && String(parsed) === value.trim()) {
          this.retry = parsed;
        }
        break;
      }
    }
  }

  private dispatchEvent(): void {
    if (this.dataLines.length === 0) {
      this.eventType = "";
      return;
    }

    const event: ServerSentEvent = {
      event: this.eventType || "message",
      data: this.dataLines.join("\n"),
      id: this.lastEventId,
      retry: this.retry,
    };

    this.events.push(event);
    this.dataLines = [];
    this.dataSize = 0;
    this.eventType = "";
    this.retry = undefined;
  }
}

/**
 * Async generator that yields parsed {@link ServerSentEvent} objects from
 * a `Readable` stream. Useful for consuming SSE responses from
 * `NLcURLResponse.body` in streaming mode.
 *
 * @param {Readable} stream - The response body stream (must be text/event-stream).
 * @yields {ServerSentEvent} Each complete SSE event as it arrives.
 *
 * @example
 * const response = await session.get(url, { stream: true });
 * for await (const event of parseSSEStream(response.body!)) {
 *   console.log(event.event, event.data);
 * }
 */
export async function* parseSSEStream(stream: Readable): AsyncGenerator<ServerSentEvent, void, undefined> {
  const parser = new SSEParser();

  for await (const chunk of stream) {
    const text = typeof chunk === "string" ? chunk : (chunk as Buffer).toString("utf8");
    parser.feed(text);
    let event: ServerSentEvent | null;
    while ((event = parser.pull()) !== null) {
      yield event;
    }
  }

  parser.flush();
  let event: ServerSentEvent | null;
  while ((event = parser.pull()) !== null) {
    yield event;
  }
}
