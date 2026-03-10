import { describe, it, beforeEach, afterEach } from "node:test";
import { strict as assert } from "node:assert";
import { ConsoleLogger, JsonLogger, SILENT_LOGGER } from "../../src/utils/logger.js";
import type { Logger } from "../../src/utils/logger.js";

describe("ConsoleLogger", () => {
  let originalWrite: typeof process.stderr.write;
  let captured: string[];

  beforeEach(() => {
    captured = [];
    originalWrite = process.stderr.write;
    process.stderr.write = ((chunk: string | Uint8Array) => {
      captured.push(typeof chunk === "string" ? chunk : Buffer.from(chunk).toString());
      return true;
    }) as typeof process.stderr.write;
  });

  afterEach(() => {
    process.stderr.write = originalWrite;
  });

  describe("level filtering", () => {
    it("outputs messages at or above the configured level", () => {
      const logger = new ConsoleLogger("warn");
      logger.debug("d");
      logger.info("i");
      logger.warn("w");
      logger.error("e");
      assert.equal(captured.length, 2);
      assert.ok(captured[0]!.includes("w"));
      assert.ok(captured[1]!.includes("e"));
    });

    it("debug level outputs all messages", () => {
      const logger = new ConsoleLogger("debug");
      logger.debug("d");
      logger.info("i");
      logger.warn("w");
      logger.error("e");
      assert.equal(captured.length, 4);
    });

    it("error level outputs only errors", () => {
      const logger = new ConsoleLogger("error");
      logger.debug("d");
      logger.info("i");
      logger.warn("w");
      logger.error("e");
      assert.equal(captured.length, 1);
      assert.ok(captured[0]!.includes("e"));
    });

    it("silent level outputs nothing", () => {
      const logger = new ConsoleLogger("silent");
      logger.debug("d");
      logger.info("i");
      logger.warn("w");
      logger.error("e");
      assert.equal(captured.length, 0);
    });
  });

  describe("output format", () => {
    it("includes nlcurl tag and level", () => {
      const logger = new ConsoleLogger("debug");
      logger.debug("test message");
      assert.ok(captured[0]!.includes("[nlcurl:debug]"));
      assert.ok(captured[0]!.includes("test message"));
    });

    it("includes prefix when set", () => {
      const logger = new ConsoleLogger("debug", "http");
      logger.info("req");
      assert.ok(captured[0]!.includes("[nlcurl:http:info]"));
    });

    it("formats additional string args", () => {
      const logger = new ConsoleLogger("debug");
      logger.debug("msg", "extra");
      assert.ok(captured[0]!.includes("msg extra"));
    });

    it("JSON-stringifies non-string args", () => {
      const logger = new ConsoleLogger("debug");
      logger.debug("msg", { key: "val" });
      assert.ok(captured[0]!.includes('{"key":"val"}'));
    });

    it("appends newline", () => {
      const logger = new ConsoleLogger("debug");
      logger.debug("msg");
      assert.ok(captured[0]!.endsWith("\n"));
    });
  });

  describe("setLevel", () => {
    it("changes the minimum log level at runtime", () => {
      const logger = new ConsoleLogger("error");
      logger.warn("before");
      assert.equal(captured.length, 0);
      logger.setLevel("warn");
      logger.warn("after");
      assert.equal(captured.length, 1);
    });
  });

  describe("child", () => {
    it("creates child logger with component prefix", () => {
      const parent = new ConsoleLogger("debug", "parent");
      const child = parent.child({ component: "child" });
      child.debug("test");
      assert.ok(captured[0]!.includes("parent:child"));
    });

    it("inherits parent level", () => {
      const parent = new ConsoleLogger("error");
      const child = parent.child({ component: "c" });
      child.warn("w");
      assert.equal(captured.length, 0);
      child.error("e");
      assert.equal(captured.length, 1);
    });

    it("merges bindings from parent", () => {
      const parent = new ConsoleLogger("debug", "", { requestId: "abc" });
      const child = parent.child({ component: "test", traceId: "xyz" });
      assert.ok(child instanceof ConsoleLogger);
    });

    it("handles missing component in bindings", () => {
      const parent = new ConsoleLogger("debug", "base");
      const child = parent.child({ other: "val" });
      child.debug("msg");
      assert.ok(captured[0]!.includes("base"));
    });
  });

  describe("defaults", () => {
    it("defaults to warn level with empty prefix", () => {
      const logger = new ConsoleLogger();
      logger.info("should not appear");
      assert.equal(captured.length, 0);
      logger.warn("should appear");
      assert.equal(captured.length, 1);
      assert.ok(captured[0]!.includes("[nlcurl:warn]"));
    });
  });
});

describe("JsonLogger", () => {
  let originalWrite: typeof process.stderr.write;
  let captured: string[];

  beforeEach(() => {
    captured = [];
    originalWrite = process.stderr.write;
    process.stderr.write = ((chunk: string | Uint8Array) => {
      captured.push(typeof chunk === "string" ? chunk : Buffer.from(chunk).toString());
      return true;
    }) as typeof process.stderr.write;
  });

  afterEach(() => {
    process.stderr.write = originalWrite;
  });

  describe("output format", () => {
    it("emits valid JSON with required fields", () => {
      const logger = new JsonLogger("debug", "test-service");
      logger.info("hello");
      assert.equal(captured.length, 1);
      const entry = JSON.parse(captured[0]!);
      assert.equal(entry.level, "info");
      assert.equal(entry.message, "hello");
      assert.equal(entry.service, "test-service");
      assert.ok(entry.timestamp);
    });

    it("includes ISO 8601 timestamp", () => {
      const logger = new JsonLogger("debug");
      logger.debug("ts-check");
      const entry = JSON.parse(captured[0]!);
      assert.ok(/^\d{4}-\d{2}-\d{2}T/.test(entry.timestamp));
    });

    it("includes metadata for extra args", () => {
      const logger = new JsonLogger("debug");
      logger.debug("msg", { a: 1 }, "extra");
      const entry = JSON.parse(captured[0]!);
      assert.ok(Array.isArray(entry.metadata));
      assert.equal(entry.metadata.length, 2);
    });

    it("omits metadata when no extra args", () => {
      const logger = new JsonLogger("debug");
      logger.debug("msg");
      const entry = JSON.parse(captured[0]!);
      assert.equal(entry.metadata, undefined);
    });

    it("includes bindings in output", () => {
      const logger = new JsonLogger("debug", "svc", { requestId: "abc" });
      logger.debug("msg");
      const entry = JSON.parse(captured[0]!);
      assert.equal(entry.requestId, "abc");
    });

    it("appends newline", () => {
      const logger = new JsonLogger("debug");
      logger.debug("msg");
      assert.ok(captured[0]!.endsWith("\n"));
    });
  });

  describe("level filtering", () => {
    it("filters messages below threshold", () => {
      const logger = new JsonLogger("warn");
      logger.debug("d");
      logger.info("i");
      logger.warn("w");
      logger.error("e");
      assert.equal(captured.length, 2);
    });
  });

  describe("setLevel", () => {
    it("changes level at runtime", () => {
      const logger = new JsonLogger("error");
      logger.warn("hidden");
      assert.equal(captured.length, 0);
      logger.setLevel("debug");
      logger.debug("visible");
      assert.equal(captured.length, 1);
    });
  });

  describe("child", () => {
    it("creates child with merged bindings", () => {
      const parent = new JsonLogger("debug", "svc", { a: 1 });
      const child = parent.child({ b: 2 });
      child.debug("test");
      const entry = JSON.parse(captured[0]!);
      assert.equal(entry.a, 1);
      assert.equal(entry.b, 2);
      assert.equal(entry.service, "svc");
    });

    it("child bindings override parent bindings", () => {
      const parent = new JsonLogger("debug", "svc", { key: "parent" });
      const child = parent.child({ key: "child" });
      child.debug("test");
      const entry = JSON.parse(captured[0]!);
      assert.equal(entry.key, "child");
    });
  });

  describe("defaults", () => {
    it("defaults to warn level with 'nlcurl' service", () => {
      const logger = new JsonLogger();
      logger.info("hidden");
      assert.equal(captured.length, 0);
      logger.warn("shown");
      assert.equal(captured.length, 1);
      const entry = JSON.parse(captured[0]!);
      assert.equal(entry.service, "nlcurl");
    });
  });
});

describe("SILENT_LOGGER", () => {
  it("implements Logger interface", () => {
    const logger: Logger = SILENT_LOGGER;
    assert.equal(typeof logger.debug, "function");
    assert.equal(typeof logger.info, "function");
    assert.equal(typeof logger.warn, "function");
    assert.equal(typeof logger.error, "function");
  });

  it("discards all messages without error", () => {
    SILENT_LOGGER.debug("test");
    SILENT_LOGGER.info("test");
    SILENT_LOGGER.warn("test");
    SILENT_LOGGER.error("test");
  });
});
