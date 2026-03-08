import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { Readable } from "node:stream";
import { SSEParser, parseSSEStream } from "../../src/sse/parser.js";

describe("SSEParser", () => {
  it("parses a simple event", () => {
    const parser = new SSEParser();
    parser.feed("data: hello\n\n");
    const event = parser.pull();
    assert.ok(event);
    assert.equal(event.event, "message");
    assert.equal(event.data, "hello");
    assert.equal(event.id, "");
  });

  it("parses named event with id", () => {
    const parser = new SSEParser();
    parser.feed("event: update\ndata: payload\nid: 42\n\n");
    const event = parser.pull();
    assert.ok(event);
    assert.equal(event.event, "update");
    assert.equal(event.data, "payload");
    assert.equal(event.id, "42");
  });

  it("parses multi-line data", () => {
    const parser = new SSEParser();
    parser.feed("data: line1\ndata: line2\ndata: line3\n\n");
    const event = parser.pull();
    assert.ok(event);
    assert.equal(event.data, "line1\nline2\nline3");
  });

  it("ignores comments", () => {
    const parser = new SSEParser();
    parser.feed(": this is a comment\ndata: value\n\n");
    const event = parser.pull();
    assert.ok(event);
    assert.equal(event.data, "value");
  });

  it("parses retry field", () => {
    const parser = new SSEParser();
    parser.feed("retry: 3000\ndata: x\n\n");
    const event = parser.pull();
    assert.ok(event);
    assert.equal(event.retry, 3000);
  });

  it("ignores invalid retry values", () => {
    const parser = new SSEParser();
    parser.feed("retry: abc\ndata: x\n\n");
    const event = parser.pull();
    assert.ok(event);
    assert.equal(event.retry, undefined);
  });

  it("returns null when no events are ready", () => {
    const parser = new SSEParser();
    parser.feed("data: partial");
    assert.equal(parser.pull(), null);
  });

  it("handles incremental feeding", () => {
    const parser = new SSEParser();
    parser.feed("data: hel");
    parser.feed("lo\n\n");
    const event = parser.pull();
    assert.ok(event);
    assert.equal(event.data, "hello");
  });

  it("handles field without colon", () => {
    const parser = new SSEParser();
    parser.feed("data\n\n");
    const event = parser.pull();
    assert.ok(event);
    assert.equal(event.data, "");
  });

  it("strips single leading space from value", () => {
    const parser = new SSEParser();
    parser.feed("data:  two spaces\n\n");
    const event = parser.pull();
    assert.ok(event);
    assert.equal(event.data, " two spaces");
  });

  it("dispatches multiple events", () => {
    const parser = new SSEParser();
    parser.feed("data: first\n\ndata: second\n\n");
    const e1 = parser.pull();
    const e2 = parser.pull();
    assert.ok(e1);
    assert.ok(e2);
    assert.equal(e1.data, "first");
    assert.equal(e2.data, "second");
  });

  it("flush processes remaining buffer", () => {
    const parser = new SSEParser();
    parser.feed("data: final");
    parser.flush();
    const event = parser.pull();
    assert.ok(event);
    assert.equal(event.data, "final");
  });

  it("handles \\r\\n line endings", () => {
    const parser = new SSEParser();
    parser.feed("data: crlf\r\n\r\n");
    const event = parser.pull();
    assert.ok(event);
    assert.equal(event.data, "crlf");
  });

  it("handles \\r line endings", () => {
    const parser = new SSEParser();
    parser.feed("data: cr\r\r");
    const event = parser.pull();
    assert.ok(event);
    assert.equal(event.data, "cr");
  });

  it("last event id persists across events", () => {
    const parser = new SSEParser();
    parser.feed("id: 1\ndata: first\n\ndata: second\n\n");
    const e1 = parser.pull();
    const e2 = parser.pull();
    assert.ok(e1);
    assert.ok(e2);
    assert.equal(e1.id, "1");
    assert.equal(e2.id, "1");
  });
});

describe("parseSSEStream", () => {
  it("yields events from a readable stream", async () => {
    const stream = Readable.from(["data: hello\n\n", "data: world\n\n"]);
    const events = [];
    for await (const event of parseSSEStream(stream)) {
      events.push(event);
    }
    assert.equal(events.length, 2);
    assert.equal(events[0]!.data, "hello");
    assert.equal(events[1]!.data, "world");
  });

  it("handles split chunks", async () => {
    const stream = Readable.from(["data: sp", "lit\n\n"]);
    const events = [];
    for await (const event of parseSSEStream(stream)) {
      events.push(event);
    }
    assert.equal(events.length, 1);
    assert.equal(events[0]!.data, "split");
  });

  it("handles Buffer chunks", async () => {
    const stream = Readable.from([Buffer.from("data: buf\n\n")]);
    const events = [];
    for await (const event of parseSSEStream(stream)) {
      events.push(event);
    }
    assert.equal(events.length, 1);
    assert.equal(events[0]!.data, "buf");
  });
});
