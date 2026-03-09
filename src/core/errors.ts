/**
 * Base error class for all NLcURL errors, providing a machine-readable error code
 * and structured JSON serialization.
 *
 * @class
 */
export class NLcURLError extends Error {
  /** Machine-readable error code (e.g. "ERR_TLS", "ERR_TIMEOUT"). */
  public readonly code: string;

  /**
   * Creates a new NLcURLError.
   *
   * @param {string} message - Human-readable error description.
   * @param {string} code - Machine-readable error code.
   * @param {Error} [cause] - The underlying cause, if any.
   */
  constructor(message: string, code: string, cause?: Error) {
    super(message, cause ? { cause } : undefined);
    this.name = "NLcURLError";
    this.code = code;
    Object.setPrototypeOf(this, new.target.prototype);
  }

  /**
   * Serializes the error to a plain object suitable for JSON output.
   *
   * @returns {Record<string, unknown>} A plain object representation of the error.
   */
  toJSON(): Record<string, unknown> {
    const obj: Record<string, unknown> = {
      name: this.name,
      code: this.code,
      message: this.message,
    };
    if (this.stack) {
      obj["stack"] = this.stack;
    }
    if (this.cause instanceof Error) {
      obj["cause"] = this.cause instanceof NLcURLError ? this.cause.toJSON() : { name: this.cause.name, message: this.cause.message, stack: this.cause.stack };
    }
    return obj;
  }
}

/**
 * Represents a TLS-level error, optionally including a TLS alert code.
 *
 * @class
 */
export class TLSError extends NLcURLError {
  /** TLS alert description code, if available. */
  public readonly alertCode?: number;

  /**
   * Creates a new TLSError.
   *
   * @param {string} message - Human-readable error description.
   * @param {number} [alertCode] - The TLS alert code.
   * @param {Error} [cause] - The underlying cause, if any.
   */
  constructor(message: string, alertCode?: number, cause?: Error) {
    super(message, "ERR_TLS", cause);
    this.name = "TLSError";
    this.alertCode = alertCode;
  }

  /** @inheritdoc */
  override toJSON(): Record<string, unknown> {
    const obj = super.toJSON();
    if (this.alertCode !== undefined) {
      obj["alertCode"] = this.alertCode;
    }
    return obj;
  }
}

/**
 * Represents an HTTP-level error with a status code.
 *
 * @class
 */
export class HTTPError extends NLcURLError {
  /** The HTTP response status code. */
  public readonly statusCode: number;

  /**
   * Creates a new HTTPError.
   *
   * @param {string} message - Human-readable error description.
   * @param {number} statusCode - The HTTP status code.
   * @param {Error} [cause] - The underlying cause, if any.
   */
  constructor(message: string, statusCode: number, cause?: Error) {
    super(message, "ERR_HTTP", cause);
    this.name = "HTTPError";
    this.statusCode = statusCode;
  }

  /** @inheritdoc */
  override toJSON(): Record<string, unknown> {
    const obj = super.toJSON();
    obj["statusCode"] = this.statusCode;
    return obj;
  }
}

/**
 * Represents a timeout error during a specific phase of the request lifecycle.
 *
 * @class
 */
export class TimeoutError extends NLcURLError {
  /** The phase during which the timeout occurred. */
  public readonly phase: "connect" | "tls" | "response" | "total";

  /**
   * Creates a new TimeoutError.
   *
   * @param {string} message - Human-readable error description.
   * @param {"connect"|"tls"|"response"|"total"} phase - The request phase that timed out.
   * @param {Error} [cause] - The underlying cause, if any.
   */
  constructor(message: string, phase: "connect" | "tls" | "response" | "total", cause?: Error) {
    super(message, "ERR_TIMEOUT", cause);
    this.name = "TimeoutError";
    this.phase = phase;
  }

  /** @inheritdoc */
  override toJSON(): Record<string, unknown> {
    const obj = super.toJSON();
    obj["phase"] = this.phase;
    return obj;
  }
}

/**
 * Represents an error originating from a proxy connection.
 *
 * @class
 */
export class ProxyError extends NLcURLError {
  /**
   * Creates a new ProxyError.
   *
   * @param {string} message - Human-readable error description.
   * @param {Error} [cause] - The underlying cause, if any.
   */
  constructor(message: string, cause?: Error) {
    super(message, "ERR_PROXY", cause);
    this.name = "ProxyError";
  }
}

/**
 * Represents a request that was intentionally aborted via an AbortSignal.
 *
 * @class
 */
export class AbortError extends NLcURLError {
  /**
   * Creates a new AbortError.
   *
   * @param {string} [message="Request aborted"] - Human-readable error description.
   * @param {Error} [cause] - The underlying cause, if any.
   */
  constructor(message: string = "Request aborted", cause?: Error) {
    super(message, "ERR_ABORTED", cause);
    this.name = "AbortError";
  }
}

/**
 * Represents a TCP or socket-level connection failure.
 *
 * @class
 */
export class ConnectionError extends NLcURLError {
  /**
   * Creates a new ConnectionError.
   *
   * @param {string} message - Human-readable error description.
   * @param {Error} [cause] - The underlying cause, if any.
   */
  constructor(message: string, cause?: Error) {
    super(message, "ERR_CONNECTION", cause);
    this.name = "ConnectionError";
  }
}

/**
 * Represents an HTTP protocol-level violation, optionally including an HTTP/2 error code.
 *
 * @class
 */
export class ProtocolError extends NLcURLError {
  /** HTTP/2 error code, if applicable. */
  public readonly errorCode?: number;

  /**
   * Creates a new ProtocolError.
   *
   * @param {string} message - Human-readable error description.
   * @param {number} [errorCode] - The protocol-level error code.
   * @param {Error} [cause] - The underlying cause, if any.
   */
  constructor(message: string, errorCode?: number, cause?: Error) {
    super(message, "ERR_PROTOCOL", cause);
    this.name = "ProtocolError";
    this.errorCode = errorCode;
  }

  /** @inheritdoc */
  override toJSON(): Record<string, unknown> {
    const obj = super.toJSON();
    if (this.errorCode !== undefined) {
      obj["errorCode"] = this.errorCode;
    }
    return obj;
  }
}
