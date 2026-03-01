/**
 * Structured logger with configurable verbosity.
 */

export type LogLevel = 'debug' | 'info' | 'warn' | 'error' | 'silent';

const LEVEL_ORDER: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
  silent: 4,
};

export interface Logger {
  debug(message: string, ...args: unknown[]): void;
  info(message: string, ...args: unknown[]): void;
  warn(message: string, ...args: unknown[]): void;
  error(message: string, ...args: unknown[]): void;
}

export class ConsoleLogger implements Logger {
  private level: number;

  constructor(level: LogLevel = 'warn') {
    this.level = LEVEL_ORDER[level];
  }

  debug(message: string, ...args: unknown[]): void {
    if (this.level <= LEVEL_ORDER.debug) {
      process.stderr.write(`[nlcurl:debug] ${message}${this.formatArgs(args)}\n`);
    }
  }

  info(message: string, ...args: unknown[]): void {
    if (this.level <= LEVEL_ORDER.info) {
      process.stderr.write(`[nlcurl:info] ${message}${this.formatArgs(args)}\n`);
    }
  }

  warn(message: string, ...args: unknown[]): void {
    if (this.level <= LEVEL_ORDER.warn) {
      process.stderr.write(`[nlcurl:warn] ${message}${this.formatArgs(args)}\n`);
    }
  }

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

/** Silent logger that discards all output. */
export const SILENT_LOGGER: Logger = {
  debug() {},
  info() {},
  warn() {},
  error() {},
};

let _default: Logger = new ConsoleLogger('warn');

export function setDefaultLogger(logger: Logger): void {
  _default = logger;
}

export function getDefaultLogger(): Logger {
  return _default;
}
