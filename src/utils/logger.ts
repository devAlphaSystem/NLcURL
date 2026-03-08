/** Severity levels for log output. */
export type LogLevel = "debug" | "info" | "warn" | "error" | "silent";

/** Structured key-value bindings attached to log messages. */
export type LogBindings = Record<string, unknown>;

const LEVEL_ORDER: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
  silent: 4,
};

/** Minimal structured logging interface. */
export interface Logger {
  /** Emit a debug-level message. */
  debug(message: string, ...args: unknown[]): void;
  /** Emit an info-level message. */
  info(message: string, ...args: unknown[]): void;
  /** Emit a warning-level message. */
  warn(message: string, ...args: unknown[]): void;
  /** Emit an error-level message. */
  error(message: string, ...args: unknown[]): void;
}

/** Logger implementation that writes to `stderr` with level filtering. */
export class ConsoleLogger implements Logger {
  private level: number;
  private readonly prefix: string;
  private readonly bindings: LogBindings;

  /**
   * Create a console logger.
   *
   * @param {LogLevel} level - Minimum severity to output.
   * @param {string} prefix - Namespace prefix for log lines.
   * @param {LogBindings} bindings - Structured context fields.
   */
  constructor(level: LogLevel = "warn", prefix: string = "", bindings: LogBindings = {}) {
    this.level = LEVEL_ORDER[level];
    this.prefix = prefix;
    this.bindings = bindings;
  }

  /**
   * Create a child logger with additional bindings.
   *
   * @param {LogBindings} bindings - Extra structured context fields.
   * @returns {ConsoleLogger} New child `ConsoleLogger`.
   */
  child(bindings: LogBindings): ConsoleLogger {
    const component = typeof bindings["component"] === "string" ? bindings["component"] : "";
    const childPrefix = this.prefix ? (component ? `${this.prefix}:${component}` : this.prefix) : component;
    const merged = { ...this.bindings, ...bindings };
    return new ConsoleLogger(this.resolveLevel(), childPrefix, merged);
  }

  /**
   * Change the minimum log level at runtime.
   *
   * @param {LogLevel} level - New severity threshold.
   */
  setLevel(level: LogLevel): void {
    this.level = LEVEL_ORDER[level];
  }

  /** Log a debug-level message. */
  debug(message: string, ...args: unknown[]): void {
    if (this.level <= LEVEL_ORDER.debug) {
      this.write("debug", message, args);
    }
  }

  /** Log an info-level message. */
  info(message: string, ...args: unknown[]): void {
    if (this.level <= LEVEL_ORDER.info) {
      this.write("info", message, args);
    }
  }

  /** Log a warning-level message. */
  warn(message: string, ...args: unknown[]): void {
    if (this.level <= LEVEL_ORDER.warn) {
      this.write("warn", message, args);
    }
  }

  /** Log an error-level message. */
  error(message: string, ...args: unknown[]): void {
    if (this.level <= LEVEL_ORDER.error) {
      this.write("error", message, args);
    }
  }

  private write(level: string, message: string, args: unknown[]): void {
    const tag = this.prefix ? `nlcurl:${this.prefix}:${level}` : `nlcurl:${level}`;
    process.stderr.write(`[${tag}] ${message}${this.formatArgs(args)}\n`);
  }

  private formatArgs(args: unknown[]): string {
    if (args.length === 0) return "";
    return " " + args.map((a) => (typeof a === "string" ? a : JSON.stringify(a))).join(" ");
  }

  private resolveLevel(): LogLevel {
    for (const [name, order] of Object.entries(LEVEL_ORDER)) {
      if (order === this.level) return name as LogLevel;
    }
    return "warn";
  }
}

/** Singleton no-op logger that discards all messages. */
export const SILENT_LOGGER: Logger = {
  debug() {},
  info() {},
  warn() {},
  error() {},
};

/** Logger implementation that writes structured JSON to `stderr` with level filtering. */
export class JsonLogger implements Logger {
  private level: number;
  private readonly service: string;
  private readonly bindings: LogBindings;

  /**
   * Create a JSON logger.
   *
   * @param {LogLevel} level - Minimum severity to output.
   * @param {string} service - Service name included in every log entry.
   * @param {LogBindings} bindings - Structured context fields.
   */
  constructor(level: LogLevel = "warn", service: string = "nlcurl", bindings: LogBindings = {}) {
    this.level = LEVEL_ORDER[level];
    this.service = service;
    this.bindings = bindings;
  }

  /**
   * Create a child JSON logger with additional bindings.
   *
   * @param {LogBindings} bindings - Extra structured context fields.
   * @returns {JsonLogger} New child `JsonLogger`.
   */
  child(bindings: LogBindings): JsonLogger {
    const merged = { ...this.bindings, ...bindings };
    return new JsonLogger(this.resolveLevel(), this.service, merged);
  }

  /**
   * Change the minimum log level at runtime.
   *
   * @param {LogLevel} level - New severity threshold.
   */
  setLevel(level: LogLevel): void {
    this.level = LEVEL_ORDER[level];
  }

  debug(message: string, ...args: unknown[]): void {
    if (this.level <= LEVEL_ORDER.debug) this.emit("debug", message, args);
  }

  info(message: string, ...args: unknown[]): void {
    if (this.level <= LEVEL_ORDER.info) this.emit("info", message, args);
  }

  warn(message: string, ...args: unknown[]): void {
    if (this.level <= LEVEL_ORDER.warn) this.emit("warn", message, args);
  }

  error(message: string, ...args: unknown[]): void {
    if (this.level <= LEVEL_ORDER.error) this.emit("error", message, args);
  }

  private emit(level: string, message: string, args: unknown[]): void {
    const entry: Record<string, unknown> = {
      timestamp: new Date().toISOString(),
      level,
      message,
      service: this.service,
    };
    for (const [k, v] of Object.entries(this.bindings)) {
      entry[k] = v;
    }
    if (args.length > 0) {
      entry["metadata"] = args;
    }
    process.stderr.write(JSON.stringify(entry) + "\n");
  }

  private resolveLevel(): LogLevel {
    for (const [name, order] of Object.entries(LEVEL_ORDER)) {
      if (order === this.level) return name as LogLevel;
    }
    return "warn";
  }
}

let _default: Logger = new ConsoleLogger("warn");

/**
 * Set the process-wide default logger.
 *
 * @param {Logger} logger - Logger instance to use as the default.
 */
export function setDefaultLogger(logger: Logger): void {
  _default = logger;
}

/** Return the current process-wide default logger. */
export function getDefaultLogger(): Logger {
  return _default;
}
