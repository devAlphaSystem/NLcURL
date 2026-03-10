import type { Readable } from "node:stream";
import type { ServerSentEvent } from "../core/request.js";

/**
 * Incremental parser for the Server-Sent Events stream format.
 *
 * Feed chunks of text with {@link feed}, then pull discrete events
 * with {@link pull}.  Call {@link flush} after the stream closes to
 * emit any buffered partial event.
 */
export class SSEParser {
  private static readonly MAX_LINE_LENGTH = 65_536;
  private static readonly MAX_EVENT_SIZE = 1_048_576;

  private bufferChunks: string[] = [];
  private bufferLength = 0;
  private eventType = "";
  private dataLines: string[] = [];
  private dataSize = 0;
  private lastEventId = "";
  private retry: number | undefined = undefined;
  private readonly events: ServerSentEvent[] = [];
  private bomStripped = false;
  private pendingCR = false;

  /**
   * Append raw text from the event stream and parse complete lines.
   *
   * @param {string} text - Chunk of UTF-8 text from the response body.
   */
  feed(text: string): void {
    if (!this.bomStripped) {
      this.bomStripped = true;
      if (text.length > 0 && text.charCodeAt(0) === 0xfeff) {
        text = text.substring(1);
      }
    }

    if (this.pendingCR) {
      this.pendingCR = false;
      if (text.length > 0 && text[0] === "\n") {
        text = text.substring(1);
      }
    }

    if (text.length > 0 && text[text.length - 1] === "\r") {
      this.pendingCR = true;
    }

    let searchFrom = 0;
    let lineStart = 0;

    let combined: string;
    if (this.bufferLength > 0) {
      const prev = this.bufferChunks.length === 1 ? this.bufferChunks[0]! : this.bufferChunks.join("");
      combined = prev + text;
      lineStart = 0;
      searchFrom = 0;
    } else {
      combined = text;
    }

    if (combined.length > SSEParser.MAX_LINE_LENGTH) {
      throw new Error(`SSE line exceeds maximum length of ${SSEParser.MAX_LINE_LENGTH} bytes`);
    }

    let lastBreak = -1;
    for (let i = searchFrom; i < combined.length; i++) {
      const ch = combined.charCodeAt(i);
      if (ch === 0x0a || ch === 0x0d) {
        const line = combined.substring(lineStart, i);
        if (ch === 0x0d && i + 1 < combined.length && combined.charCodeAt(i + 1) === 0x0a) {
          i++;
        }
        lineStart = i + 1;
        lastBreak = lineStart;
        this.processLine(line);
      }
    }

    if (lastBreak === -1) {
      this.bufferChunks = combined.length > 0 ? [combined] : [];
      this.bufferLength = combined.length;
    } else if (lineStart < combined.length) {
      const remainder = combined.substring(lineStart);
      this.bufferChunks = [remainder];
      this.bufferLength = remainder.length;
    } else {
      this.bufferChunks = [];
      this.bufferLength = 0;
    }
  }

  /**
   * Remove and return the next fully-parsed event from the queue.
   *
   * @returns {ServerSentEvent|null} The next {@link ServerSentEvent}, or `null` if the queue is empty.
   */
  pull(): ServerSentEvent | null {
    return this.events.shift() ?? null;
  }

  /** Flush any remaining buffered data and dispatch a final event if present. */
  flush(): void {
    if (this.bufferLength > 0) {
      const remaining = this.bufferChunks.length === 1 ? this.bufferChunks[0]! : this.bufferChunks.join("");
      this.processLine(remaining);
      this.bufferChunks = [];
      this.bufferLength = 0;
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
 * Consume a readable stream as a Server-Sent Events source.
 *
 * Yields individual {@link ServerSentEvent} objects as they are parsed
 * from the stream in real time.
 *
 * @param {Readable} stream - Readable stream carrying `text/event-stream` data.
 * @returns {AsyncGenerator<ServerSentEvent>} Async generator of server-sent events.
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
