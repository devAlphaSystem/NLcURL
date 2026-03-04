/**
 * Minimum severity level for log emission. Messages below this level are
 * suppressed. `'silent'` disables all output.
 *
 * @typedef {'debug' | 'info' | 'warn' | 'error' | 'silent'} LogLevel
 */
export type LogLevel = "debug" | "info" | "warn" | "error" | "silent";

/**
 * Key-value metadata attached to every log entry produced by a child logger.
 * Bindings are inherited from parent to child, allowing nested scoping.
 *
 * @typedef {Record<string, unknown>} LogBindings
 */
export type LogBindings = Record<string, unknown>;

const LEVEL_ORDER: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
  silent: 4,
};

/**
 * Minimal logger interface consumed throughout the library. Implementations
 * must provide four severity methods; all parameters follow `console.log`
 * semantics (a primary message string followed by optional extra values).
 */
export interface Logger {
  /** Emits a diagnostic message useful only during development. */
  debug(message: string, ...args: unknown[]): void;
  /** Emits a significant lifecycle or business event. */
  info(message: string, ...args: unknown[]): void;
  /** Emits a warning about an unexpected but recoverable condition. */
  warn(message: string, ...args: unknown[]): void;
  /** Emits an error indicating an operation failure that requires attention. */
  error(message: string, ...args: unknown[]): void;
}

/**
 * Default {@link Logger} implementation that writes to `process.stderr`.
 * Messages are prefixed with `[nlcurl:<level>]` and only emitted when the
 * message severity meets or exceeds the configured `level`.
 *
 * Supports scoped child loggers via {@link ConsoleLogger.child}, which
 * prepend a component tag to every message for easy filtering.
 */
export class ConsoleLogger implements Logger {
  private level: number;
  private readonly prefix: string;
  private readonly bindings: LogBindings;

  /**
   * Creates a new ConsoleLogger.
   *
   * @param {LogLevel}    [level='warn'] - Minimum severity level to emit.
   * @param {string}      [prefix='']    - Component prefix prepended to every message.
   * @param {LogBindings} [bindings={}]  - Key-value metadata appended to every message.
   */
  constructor(level: LogLevel = "warn", prefix: string = "", bindings: LogBindings = {}) {
    this.level = LEVEL_ORDER[level];
    this.prefix = prefix;
    this.bindings = bindings;
  }

  /**
   * Creates a child logger that inherits this logger's level and prepends
   * an additional component tag to every message. Bindings from the parent
   * are merged with the child's bindings (child values win on conflict).
   *
   * @param {LogBindings} bindings - Additional metadata for the child scope.
   * @returns {ConsoleLogger} A new scoped logger instance.
   *
   * @example
   * const logger = new ConsoleLogger('debug');
   * const child = logger.child({ component: 'h2' });
   * child.debug('stream opened', { streamId: 1 });
   */
  child(bindings: LogBindings): ConsoleLogger {
    const component = typeof bindings["component"] === "string" ? bindings["component"] : "";
    const childPrefix = this.prefix ? (component ? `${this.prefix}:${component}` : this.prefix) : component;
    const merged = { ...this.bindings, ...bindings };
    return new ConsoleLogger(this.resolveLevel(), childPrefix, merged);
  }

  /**
   * Updates the minimum severity level at runtime without creating a new
   * logger instance.
   *
   * @param {LogLevel} level - New minimum severity level.
   */
  setLevel(level: LogLevel): void {
    this.level = LEVEL_ORDER[level];
  }

  /**
   * Emits a debug-level message to `stderr` -- only written when the
   * configured minimum level is `'debug'`.
   *
   * @param {string}    message - Primary log message.
   * @param {...unknown} args   - Additional values appended after the message.
   */
  debug(message: string, ...args: unknown[]): void {
    if (this.level <= LEVEL_ORDER.debug) {
      this.write("debug", message, args);
    }
  }

  /**
   * Emits an info-level message to `stderr` -- only written when the
   * configured minimum level is `'debug'` or `'info'`.
   *
   * @param {string}    message - Primary log message.
   * @param {...unknown} args   - Additional values appended after the message.
   */
  info(message: string, ...args: unknown[]): void {
    if (this.level <= LEVEL_ORDER.info) {
      this.write("info", message, args);
    }
  }

  /**
   * Emits a warn-level message to `stderr` -- only written when the
   * configured minimum level is `'debug'`, `'info'`, or `'warn'`.
   *
   * @param {string}    message - Primary log message.
   * @param {...unknown} args   - Additional values appended after the message.
   */
  warn(message: string, ...args: unknown[]): void {
    if (this.level <= LEVEL_ORDER.warn) {
      this.write("warn", message, args);
    }
  }

  /**
   * Emits an error-level message to `stderr` -- only written when the
   * configured minimum level is not `'silent'`.
   *
   * @param {string}    message - Primary log message.
   * @param {...unknown} args   - Additional values appended after the message.
   */
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

/**
 * A no-op {@link Logger} that discards all messages. Assign this via
 * {@link setDefaultLogger} to silence the library entirely.
 */
export const SILENT_LOGGER: Logger = {
  debug() {},
  info() {},
  warn() {},
  error() {},
};

let _default: Logger = new ConsoleLogger("warn");

/**
 * Replaces the process-wide default logger used by all NLcURL internals.
 *
 * @param {Logger} logger - New logger instance to install.
 */
export function setDefaultLogger(logger: Logger): void {
  _default = logger;
}

/**
 * Returns the currently active process-wide logger.
 *
 * @returns {Logger} The active logger instance.
 */
export function getDefaultLogger(): Logger {
  return _default;
}
