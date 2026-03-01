/**
 * NLcURL error hierarchy.
 *
 * All errors thrown by the library extend NLcURLError so callers can
 * discriminate library faults from generic exceptions with a single
 * instanceof check.
 */

export class NLcURLError extends Error {
  public readonly code: string;

  constructor(message: string, code: string) {
    super(message);
    this.name = 'NLcURLError';
    this.code = code;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class TLSError extends NLcURLError {
  public readonly alertCode?: number;

  constructor(message: string, alertCode?: number) {
    super(message, 'ERR_TLS');
    this.name = 'TLSError';
    this.alertCode = alertCode;
  }
}

export class HTTPError extends NLcURLError {
  public readonly statusCode: number;

  constructor(message: string, statusCode: number) {
    super(message, 'ERR_HTTP');
    this.name = 'HTTPError';
    this.statusCode = statusCode;
  }
}

export class TimeoutError extends NLcURLError {
  public readonly phase: 'connect' | 'tls' | 'response' | 'total';

  constructor(message: string, phase: 'connect' | 'tls' | 'response' | 'total') {
    super(message, 'ERR_TIMEOUT');
    this.name = 'TimeoutError';
    this.phase = phase;
  }
}

export class ProxyError extends NLcURLError {
  constructor(message: string) {
    super(message, 'ERR_PROXY');
    this.name = 'ProxyError';
  }
}

export class AbortError extends NLcURLError {
  constructor(message: string = 'Request aborted') {
    super(message, 'ERR_ABORTED');
    this.name = 'AbortError';
  }
}

export class ConnectionError extends NLcURLError {
  constructor(message: string) {
    super(message, 'ERR_CONNECTION');
    this.name = 'ConnectionError';
  }
}

export class ProtocolError extends NLcURLError {
  constructor(message: string) {
    super(message, 'ERR_PROTOCOL');
    this.name = 'ProtocolError';
  }
}
