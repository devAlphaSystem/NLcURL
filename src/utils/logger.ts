
/**
 * Minimum severity level for log emission. Messages below this level are
 * suppressed. `'silent'` disables all output.
 *
 * @typedef {'debug' | 'info' | 'warn' | 'error' | 'silent'} LogLevel
 */
export type LogLevel = 'debug' | 'info' | 'warn' | 'error' | 'silent';

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
  debug(message: string, ...args: unknown[]): void;
  info(message: string, ...args: unknown[]): void;
  warn(message: string, ...args: unknown[]): void;
  error(message: string, ...args: unknown[]): void;
}

/**
 * Default {@link Logger} implementation that writes to `process.stderr`.
 * Messages are prefixed with `[nlcurl:<level>]` and only emitted when the
 * message severity meets or exceeds the configured `level`.
 */
export class ConsoleLogger implements Logger {
  private level: number;

  /**
   * Creates a new ConsoleLogger.
   *
   * @param {LogLevel} [level='warn'] - Minimum severity level to emit.
   */
  constructor(level: LogLevel = 'warn') {
    this.level = LEVEL_ORDER[level];
  }

  /**
   * Emits a debug-level message to `stderr` — only written when the
   * configured minimum level is `'debug'`.
   *
   * @param {string}    message - Primary log message.
   * @param {...unknown} args   - Additional values appended after the message.
   */
  debug(message: string, ...args: unknown[]): void {
    if (this.level <= LEVEL_ORDER.debug) {
      process.stderr.write(`[nlcurl:debug] ${message}${this.formatArgs(args)}\n`);
    }
  }

  /**
   * Emits an info-level message to `stderr` — only written when the
   * configured minimum level is `'debug'` or `'info'`.
   *
   * @param {string}    message - Primary log message.
   * @param {...unknown} args   - Additional values appended after the message.
   */
  info(message: string, ...args: unknown[]): void {
    if (this.level <= LEVEL_ORDER.info) {
      process.stderr.write(`[nlcurl:info] ${message}${this.formatArgs(args)}\n`);
    }
  }

  /**
   * Emits a warn-level message to `stderr` — only written when the
   * configured minimum level is `'debug'`, `'info'`, or `'warn'`.
   *
   * @param {string}    message - Primary log message.
   * @param {...unknown} args   - Additional values appended after the message.
   */
  warn(message: string, ...args: unknown[]): void {
    if (this.level <= LEVEL_ORDER.warn) {
      process.stderr.write(`[nlcurl:warn] ${message}${this.formatArgs(args)}\n`);
    }
  }

  /**
   * Emits an error-level message to `stderr` — only written when the
   * configured minimum level is not `'silent'`.
   *
   * @param {string}    message - Primary log message.
   * @param {...unknown} args   - Additional values appended after the message.
   */
  error(message: string, ...args: unknown[]): void {
    if (this.level <= LEVEL_ORDER.error) {
      process.stderr.write(`[nlcurl:error] ${message}${this.formatArgs(args)}\n`);
    }
  }

  private formatArgs(args: unknown[]): string {
    if (args.length === 0) return '';
    return ' ' + args.map((a) => (typeof a === 'string' ? a : JSON.stringify(a))).join(' ');
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

let _default: Logger = new ConsoleLogger('warn');

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
