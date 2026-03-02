
/**
 * Base error class for all NLcURL library errors. All library-specific
 * errors extend this class, allowing callers to distinguish NLcURL failures
 * from native Node.js or third-party errors via `instanceof NLcURLError`.
 */
export class NLcURLError extends Error {
  /** Machine-readable error code string (e.g. `"ERR_TLS"`, `"ERR_TIMEOUT"`). */
  public readonly code: string;

  /**
   * Creates a new NLcURLError instance.
   *
   * @param {string} message - Human-readable description of the error.
   * @param {string} code    - Machine-readable error code identifying the failure category.
   */
  constructor(message: string, code: string) {
    super(message);
    this.name = 'NLcURLError';
    this.code = code;
    Object.setPrototypeOf(this, new.target.prototype);
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
   * @param {string} message          - Human-readable description of the TLS failure.
   * @param {number} [alertCode]      - Optional TLS alert description code (RFC 8446 §6).
   */
  constructor(message: string, alertCode?: number) {
    super(message, 'ERR_TLS');
    this.name = 'TLSError';
    this.alertCode = alertCode;
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
   */
  constructor(message: string, statusCode: number) {
    super(message, 'ERR_HTTP');
    this.name = 'HTTPError';
    this.statusCode = statusCode;
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
   * - `"connect"` — TCP connection establishment exceeded the limit.
   * - `"tls"` — TLS handshake exceeded the limit.
   * - `"response"` — Waiting for the first response byte exceeded the limit.
   * - `"total"` — The overall wall-clock duration exceeded the limit.
   */
  public readonly phase: 'connect' | 'tls' | 'response' | 'total';

  /**
   * Creates a new TimeoutError instance.
   *
   * @param {string} message                                    - Human-readable description.
   * @param {'connect'|'tls'|'response'|'total'} phase          - The phase that timed out.
   */
  constructor(message: string, phase: 'connect' | 'tls' | 'response' | 'total') {
    super(message, 'ERR_TIMEOUT');
    this.name = 'TimeoutError';
    this.phase = phase;
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
   */
  constructor(message: string) {
    super(message, 'ERR_PROXY');
    this.name = 'ProxyError';
  }
}

/**
 * Raised when a request is cancelled via an `AbortSignal`. Unlike other
 * errors, an `AbortError` is never retried — it propagates immediately.
 */
export class AbortError extends NLcURLError {
  /**
   * Creates a new AbortError instance.
   *
   * @param {string} [message='Request aborted'] - Human-readable description.
   */
  constructor(message: string = 'Request aborted') {
    super(message, 'ERR_ABORTED');
    this.name = 'AbortError';
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
   */
  constructor(message: string) {
    super(message, 'ERR_CONNECTION');
    this.name = 'ConnectionError';
  }
}

/**
 * Raised when an HTTP/2 or HTTP/1.1 protocol violation is detected, such as
 * an invalid frame, an unexpected stream state, or a GOAWAY from the server.
 * Certain HTTP/2 error codes (e.g. `REFUSED_STREAM`) are retryable.
 */
export class ProtocolError extends NLcURLError {
  /** The HTTP/2 error code (RFC 9113 §7), if this error originates from an H2 frame. */
  public readonly errorCode?: number;

  /**
   * Creates a new ProtocolError instance.
   *
   * @param {string} message      - Human-readable description of the protocol error.
   * @param {number} [errorCode]  - Optional HTTP/2 protocol error code (RFC 9113 §7).
   */
  constructor(message: string, errorCode?: number) {
    super(message, 'ERR_PROTOCOL');
    this.name = 'ProtocolError';
    this.errorCode = errorCode;
  }
}
