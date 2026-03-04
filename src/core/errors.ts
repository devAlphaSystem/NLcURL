/**
 * Base error class for all NLcURL library errors. All library-specific
 * errors extend this class, allowing callers to distinguish NLcURL failures
 * from native Node.js or third-party errors via `instanceof NLcURLError`.
 *
 * Supports ES2022 error chaining through the standard `cause` property.
 * When wrapping a lower-level error, pass it as the `cause` parameter to
 * preserve the full error chain for diagnostics.
 */
export class NLcURLError extends Error {
  /** Machine-readable error code string (e.g. `"ERR_TLS"`, `"ERR_TIMEOUT"`). */
  public readonly code: string;

  /**
   * Creates a new NLcURLError instance.
   *
   * @param {string} message - Human-readable description of the error.
   * @param {string} code    - Machine-readable error code identifying the failure category.
   * @param {Error}  [cause] - Optional underlying error that triggered this one.
   */
  constructor(message: string, code: string, cause?: Error) {
    super(message, cause ? { cause } : undefined);
    this.name = "NLcURLError";
    this.code = code;
    Object.setPrototypeOf(this, new.target.prototype);
  }

  /**
   * Serializes the error into a plain object suitable for structured logging
   * or JSON API responses. Recursively serializes the `cause` chain.
   *
   * @returns {Object} A JSON-safe representation of the error.
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
 * Raised when a TLS handshake fails, a certificate is invalid, or any other
 * TLS-layer error occurs during connection establishment or data transfer.
 */
export class TLSError extends NLcURLError {
  /** TLS alert description code from RFC 8446, if the server sent an Alert record. */
  public readonly alertCode?: number;

  /**
   * Creates a new TLSError instance.
   *
   * @param {string} message     - Human-readable description of the TLS failure.
   * @param {number} [alertCode] - Optional TLS alert description code (RFC 8446 section 6).
   * @param {Error}  [cause]     - Optional underlying error that triggered this one.
   */
  constructor(message: string, alertCode?: number, cause?: Error) {
    super(message, "ERR_TLS", cause);
    this.name = "TLSError";
    this.alertCode = alertCode;
  }

  /**
   * Serializes the error including the TLS alert code.
   *
   * @returns {Object} A JSON-safe representation of the error.
   */
  override toJSON(): Record<string, unknown> {
    const obj = super.toJSON();
    if (this.alertCode !== undefined) {
      obj["alertCode"] = this.alertCode;
    }
    return obj;
  }
}

/**
 * Raised when an HTTP-level error occurs, such as a protocol violation or a
 * connection close before the response is complete. This is distinct from
 * non-2xx responses, which are returned as successful `NLcURLResponse` objects.
 */
export class HTTPError extends NLcURLError {
  /** The HTTP status code associated with the error, or `0` if unavailable. */
  public readonly statusCode: number;

  /**
   * Creates a new HTTPError instance.
   *
   * @param {string} message    - Human-readable description of the HTTP error.
   * @param {number} statusCode - The HTTP status code, or `0` if none applies.
   * @param {Error}  [cause]    - Optional underlying error that triggered this one.
   */
  constructor(message: string, statusCode: number, cause?: Error) {
    super(message, "ERR_HTTP", cause);
    this.name = "HTTPError";
    this.statusCode = statusCode;
  }

  /**
   * Serializes the error including the HTTP status code.
   *
   * @returns {Object} A JSON-safe representation of the error.
   */
  override toJSON(): Record<string, unknown> {
    const obj = super.toJSON();
    obj["statusCode"] = this.statusCode;
    return obj;
  }
}

/**
 * Raised when a request exceeds a configured timeout limit. The `phase`
 * property identifies which stage of the request lifecycle timed out.
 */
export class TimeoutError extends NLcURLError {
  /**
   * The lifecycle phase in which the timeout occurred.
   *
   * - `"connect"` -- TCP connection establishment exceeded the limit.
   * - `"tls"` -- TLS handshake exceeded the limit.
   * - `"response"` -- Waiting for the first response byte exceeded the limit.
   * - `"total"` -- The overall wall-clock duration exceeded the limit.
   */
  public readonly phase: "connect" | "tls" | "response" | "total";

  /**
   * Creates a new TimeoutError instance.
   *
   * @param {string}                              message - Human-readable description.
   * @param {'connect'|'tls'|'response'|'total'} phase   - The phase that timed out.
   * @param {Error}                               [cause] - Optional underlying error.
   */
  constructor(message: string, phase: "connect" | "tls" | "response" | "total", cause?: Error) {
    super(message, "ERR_TIMEOUT", cause);
    this.name = "TimeoutError";
    this.phase = phase;
  }

  /**
   * Serializes the error including the timeout phase.
   *
   * @returns {Object} A JSON-safe representation of the error.
   */
  override toJSON(): Record<string, unknown> {
    const obj = super.toJSON();
    obj["phase"] = this.phase;
    return obj;
  }
}

/**
 * Raised when a proxy connection fails, including CONNECT tunnel failures,
 * authentication rejections, SOCKS negotiation errors, and TCP-level timeouts
 * while reaching the proxy server.
 */
export class ProxyError extends NLcURLError {
  /**
   * Creates a new ProxyError instance.
   *
   * @param {string} message - Human-readable description of the proxy failure.
   * @param {Error}  [cause] - Optional underlying error that triggered this one.
   */
  constructor(message: string, cause?: Error) {
    super(message, "ERR_PROXY", cause);
    this.name = "ProxyError";
  }
}

/**
 * Raised when a request is cancelled via an `AbortSignal`. Unlike other
 * errors, an `AbortError` is never retried -- it propagates immediately.
 */
export class AbortError extends NLcURLError {
  /**
   * Creates a new AbortError instance.
   *
   * @param {string} [message='Request aborted'] - Human-readable description.
   * @param {Error}  [cause]                     - Optional underlying error.
   */
  constructor(message: string = "Request aborted", cause?: Error) {
    super(message, "ERR_ABORTED", cause);
    this.name = "AbortError";
  }
}

/**
 * Raised when a TCP connection cannot be established or is unexpectedly reset
 * before a response is received. This error is retryable according to the
 * default retry policy.
 */
export class ConnectionError extends NLcURLError {
  /**
   * Creates a new ConnectionError instance.
   *
   * @param {string} message - Human-readable description of the connection failure.
   * @param {Error}  [cause] - Optional underlying error that triggered this one.
   */
  constructor(message: string, cause?: Error) {
    super(message, "ERR_CONNECTION", cause);
    this.name = "ConnectionError";
  }
}

/**
 * Raised when an HTTP/2 or HTTP/1.1 protocol violation is detected, such as
 * an invalid frame, an unexpected stream state, or a GOAWAY from the server.
 * Certain HTTP/2 error codes (e.g. `REFUSED_STREAM`) are retryable.
 */
export class ProtocolError extends NLcURLError {
  /** The HTTP/2 error code (RFC 9113 section 7), if this error originates from an H2 frame. */
  public readonly errorCode?: number;

  /**
   * Creates a new ProtocolError instance.
   *
   * @param {string} message     - Human-readable description of the protocol error.
   * @param {number} [errorCode] - Optional HTTP/2 protocol error code (RFC 9113 section 7).
   * @param {Error}  [cause]     - Optional underlying error that triggered this one.
   */
  constructor(message: string, errorCode?: number, cause?: Error) {
    super(message, "ERR_PROTOCOL", cause);
    this.name = "ProtocolError";
    this.errorCode = errorCode;
  }

  /**
   * Serializes the error including the protocol error code.
   *
   * @returns {Object} A JSON-safe representation of the error.
   */
  override toJSON(): Record<string, unknown> {
    const obj = super.toJSON();
    if (this.errorCode !== undefined) {
      obj["errorCode"] = this.errorCode;
    }
    return obj;
  }
}
