import { describe, it, beforeEach } from "node:test";
import { strict as assert } from "node:assert";
import { Readable } from "node:stream";
import { SSEParser, parseSSEStream } from "../../src/sse/parser.js";

describe("SSEParser", () => {
  let parser: SSEParser;

  beforeEach(() => {
    parser = new SSEParser();
  });

  describe("basic event parsing", () => {
    it("parses a simple data-only event (defaults to 'message' type)", () => {
      parser.feed("data: hello world\n\n");
      const event = parser.pull();
      assert.notEqual(event, null);
      assert.equal(event!.event, "message");
      assert.equal(event!.data, "hello world");
      assert.equal(event!.id, "");
    });

    it("parses named event type", () => {
      parser.feed("event: update\ndata: payload\n\n");
      const event = parser.pull();
      assert.notEqual(event, null);
      assert.equal(event!.event, "update");
      assert.equal(event!.data, "payload");
    });

    it("parses event with id field", () => {
      parser.feed("id: 42\ndata: test\n\n");
      const event = parser.pull();
      assert.notEqual(event, null);
      assert.equal(event!.id, "42");
      assert.equal(event!.data, "test");
    });

    it("parses event with retry field", () => {
      parser.feed("retry: 3000\ndata: test\n\n");
      const event = parser.pull();
      assert.notEqual(event, null);
      assert.equal(event!.retry, 3000);
    });

    it("returns null when no events are available", () => {
      assert.equal(parser.pull(), null);
    });

    it("queues multiple events", () => {
      parser.feed("data: first\n\ndata: second\n\n");
      const e1 = parser.pull();
      const e2 = parser.pull();
      const e3 = parser.pull();
      assert.equal(e1!.data, "first");
      assert.equal(e2!.data, "second");
      assert.equal(e3, null);
    });
  });

  describe("multi-line data per WHATWG EventSource spec", () => {
    it("joins multiple data lines with newline", () => {
      parser.feed("data: line1\ndata: line2\ndata: line3\n\n");
      const event = parser.pull();
      assert.equal(event!.data, "line1\nline2\nline3");
    });

    it("handles data with empty value", () => {
      parser.feed("data\n\n");
      const event = parser.pull();
      assert.equal(event!.data, "");
    });

    it("handles data with colon but no space", () => {
      parser.feed("data:no-space\n\n");
      const event = parser.pull();
      assert.equal(event!.data, "no-space");
    });
  });

  describe("comment lines", () => {
    it("ignores lines starting with colon", () => {
      parser.feed(": this is a comment\ndata: actual\n\n");
      const event = parser.pull();
      assert.equal(event!.data, "actual");
    });

    it("ignores empty comments", () => {
      parser.feed(":\ndata: test\n\n");
      const event = parser.pull();
      assert.equal(event!.data, "test");
    });
  });

  describe("line endings", () => {
    it("handles \\r\\n (CRLF) line endings", () => {
      parser.feed("data: crlf\r\n\r\n");
      const event = parser.pull();
      assert.equal(event!.data, "crlf");
    });

    it("handles \\r (CR) line endings", () => {
      parser.feed("data: cr\r\r");
      const event = parser.pull();
      assert.equal(event!.data, "cr");
    });

    it("handles mixed line endings", () => {
      parser.feed("data: mixed\r\ndata: endings\n\n");
      const event = parser.pull();
      assert.equal(event!.data, "mixed\nendings");
    });
  });

  describe("BOM stripping", () => {
    it("strips UTF-8 BOM from start of stream", () => {
      parser.feed("\uFEFFdata: bom\n\n");
      const event = parser.pull();
      assert.equal(event!.data, "bom");
    });

    it("does not strip BOM if not at start", () => {
      parser.feed("data: pre\n\n");
      parser.feed("\uFEFFdata: post\n\n");
      parser.pull();
      const event = parser.pull();
    });
  });

  describe("incremental feeding", () => {
    it("parses event split across multiple chunks", () => {
      parser.feed("dat");
      parser.feed("a: split\n");
      parser.feed("\n");
      const event = parser.pull();
      assert.equal(event!.data, "split");
    });

    it("handles empty feed chunks", () => {
      parser.feed("");
      parser.feed("data: test\n\n");
      const event = parser.pull();
      assert.equal(event!.data, "test");
    });

    it("handles CRLF split across chunks", () => {
      parser.feed("data: test\r");
      parser.feed("\n\r\n");
      const event = parser.pull();
      assert.equal(event!.data, "test");
    });
  });

  describe("id field", () => {
    it("persists last event ID across events", () => {
      parser.feed("id: 1\ndata: first\n\n");
      parser.feed("data: second\n\n");
      const e1 = parser.pull();
      const e2 = parser.pull();
      assert.equal(e1!.id, "1");
      assert.equal(e2!.id, "1");
    });

    it("rejects id containing null character per WHATWG spec", () => {
      parser.feed("id: bad\0id\ndata: test\n\n");
      const event = parser.pull();
      assert.equal(event!.id, "");
    });

    it("updates id with valid value", () => {
      parser.feed("id: first\ndata: a\n\n");
      parser.feed("id: second\ndata: b\n\n");
      const e1 = parser.pull();
      const e2 = parser.pull();
      assert.equal(e1!.id, "first");
      assert.equal(e2!.id, "second");
    });
  });

  describe("retry field", () => {
    it("parses integer retry value", () => {
      parser.feed("retry: 5000\ndata: test\n\n");
      const event = parser.pull();
      assert.equal(event!.retry, 5000);
    });

    it("ignores non-integer retry values", () => {
      parser.feed("retry: abc\ndata: test\n\n");
      const event = parser.pull();
      assert.equal(event!.retry, undefined);
    });

    it("ignores retry with decimal values", () => {
      parser.feed("retry: 3.5\ndata: test\n\n");
      const event = parser.pull();
      assert.equal(event!.retry, undefined);
    });

    it("handles retry: 0", () => {
      parser.feed("retry: 0\ndata: test\n\n");
      const event = parser.pull();
      assert.equal(event!.retry, 0);
    });
  });

  describe("empty line dispatch", () => {
    it("does not dispatch when no data lines accumulated", () => {
      parser.feed("event: noop\n\n");
      assert.equal(parser.pull(), null);
    });

    it("resets event type after dispatch", () => {
      parser.feed("event: custom\ndata: a\n\ndata: b\n\n");
      const e1 = parser.pull();
      const e2 = parser.pull();
      assert.equal(e1!.event, "custom");
      assert.equal(e2!.event, "message");
    });
  });

  describe("flush", () => {
    it("dispatches buffered event on stream end", () => {
      parser.feed("data: no-trailing-newline");
      assert.equal(parser.pull(), null);
      parser.flush();
      const event = parser.pull();
      assert.notEqual(event, null);
      assert.equal(event!.data, "no-trailing-newline");
    });

    it("no-ops when buffer is empty", () => {
      parser.flush();
      assert.equal(parser.pull(), null);
    });
  });

  describe("field value space stripping", () => {
    it("strips single leading space after colon", () => {
      parser.feed("data: spaced\n\n");
      const event = parser.pull();
      assert.equal(event!.data, "spaced");
    });

    it("does not strip multiple leading spaces", () => {
      parser.feed("data:  two-spaces\n\n");
      const event = parser.pull();
      assert.equal(event!.data, " two-spaces");
    });

    it("handles field with just colon (empty value)", () => {
      parser.feed("data:\n\n");
      const event = parser.pull();
      assert.equal(event!.data, "");
    });
  });

  describe("unknown fields", () => {
    it("ignores unknown field names per spec", () => {
      parser.feed("unknown: value\ndata: test\n\n");
      const event = parser.pull();
      assert.equal(event!.data, "test");
    });
  });

  describe("size limits", () => {
    it("rejects line exceeding MAX_LINE_LENGTH (65536)", () => {
      const longLine = "data: " + "x".repeat(65536);
      assert.throws(() => {
        parser.feed(longLine);
      }, /maximum length/);
    });

    it("rejects event data exceeding MAX_EVENT_SIZE (1048576)", () => {
      const line = "data: " + "A".repeat(10000) + "\n";
      assert.throws(() => {
        for (let i = 0; i < 150; i++) {
          parser.feed(line);
        }
      }, /maximum size/);
    });
  });

  describe("parseSSEStream", () => {
    it("yields events from a readable stream", async () => {
      const chunks = ["data: hello\n\n", "event: update\ndata: world\n\n"];
      const stream = Readable.from(chunks);

      const events = [];
      for await (const event of parseSSEStream(stream)) {
        events.push(event);
      }

      assert.equal(events.length, 2);
      assert.equal(events[0]!.event, "message");
      assert.equal(events[0]!.data, "hello");
      assert.equal(events[1]!.event, "update");
      assert.equal(events[1]!.data, "world");
    });

    it("handles chunked data split across stream reads", async () => {
      const stream = Readable.from(["data: sp", "lit\n", "\n"]);

      const events = [];
      for await (const event of parseSSEStream(stream)) {
        events.push(event);
      }

      assert.equal(events.length, 1);
      assert.equal(events[0]!.data, "split");
    });

    it("flushes remaining data at stream end", async () => {
      const stream = Readable.from(["data: final"]);

      const events = [];
      for await (const event of parseSSEStream(stream)) {
        events.push(event);
      }

      assert.equal(events.length, 1);
      assert.equal(events[0]!.data, "final");
    });

    it("handles buffer chunks", async () => {
      const stream = Readable.from([Buffer.from("data: buf\n\n")]);

      const events = [];
      for await (const event of parseSSEStream(stream)) {
        events.push(event);
      }

      assert.equal(events.length, 1);
      assert.equal(events[0]!.data, "buf");
    });

    it("yields nothing for empty stream", async () => {
      const stream = Readable.from([]);

      const events = [];
      for await (const event of parseSSEStream(stream)) {
        events.push(event);
      }

      assert.equal(events.length, 0);
    });
  });
});
