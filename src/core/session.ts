
import type {
  NLcURLRequest,
  NLcURLSessionConfig,
  HttpMethod,
  RetryConfig,
  RequestBody,
  TimeoutConfig,
  RequestTimings,
} from './request.js';
import { NLcURLResponse } from './response.js';
import { AbortError, NLcURLError } from './errors.js';
import { ProtocolNegotiator, type NegotiatorOptions } from '../http/negotiator.js';
import { CookieJar } from '../cookies/jar.js';
import { InterceptorChain, type RequestInterceptor, type ResponseInterceptor } from '../middleware/interceptor.js';
import { RateLimiter, type RateLimitConfig } from '../middleware/rate-limiter.js';
import { withRetry } from '../middleware/retry.js';
import { getProfile, DEFAULT_PROFILE, type BrowserProfile } from '../fingerprints/database.js';
import { resolveURL, appendParams } from '../utils/url.js';

const MAX_REDIRECTS = 20;

/**
 * Request options that can be passed alongside a URL and HTTP method. All
 * fields from {@link NLcURLRequest} except `url`, `method`, and `body`.
 *
 * @typedef {Omit<NLcURLRequest, 'url'|'method'|'body'>} RequestOptions
 */
export type RequestOptions = Omit<NLcURLRequest, 'url' | 'method' | 'body'>;

/**
 * Stateful HTTP client session that persists connections, cookies, interceptors,
 * and configuration across multiple requests. Prefer using a session when making
 * many requests to the same origin, or when you need shared cookie state.
 *
 * @example
 * const session = new NLcURLSession({ impersonate: 'chrome136' });
 * const response = await session.get('https://example.com');
 * session.close();
 */
export class NLcURLSession {
  private readonly config: NLcURLSessionConfig;
  private readonly negotiator: ProtocolNegotiator;
  private readonly cookieJar: CookieJar | null;
  private readonly interceptors: InterceptorChain;
  private rateLimiter: RateLimiter | null = null;
  private closed = false;

  /**
   * Creates a new NLcURLSession.
   *
   * @param {NLcURLSessionConfig} [config={}] - Session-level defaults applied to every request.
   */
  constructor(config: NLcURLSessionConfig = {}) {
    this.config = config;
    this.negotiator = new ProtocolNegotiator();
    this.interceptors = new InterceptorChain();

    if (config.cookieJar === true || config.cookieJar === undefined) {
      this.cookieJar = new CookieJar();
    } else if (config.cookieJar === false) {
      this.cookieJar = null;
    } else {
      this.cookieJar = new CookieJar();
    }
  }

  /**
   * Registers a request interceptor that is invoked (in registration order)
   * before each request is dispatched. The interceptor may return a modified
   * request object or a `Promise` that resolves to one.
   *
   * @param {RequestInterceptor} fn - The interceptor function to add.
   * @returns {this} The session instance, enabling a fluent call chain.
   */
  onRequest(fn: RequestInterceptor): this {
    this.interceptors.addRequestInterceptor(fn);
    return this;
  }

  /**
   * Registers a response interceptor that is invoked (in registration order)
   * after each response is received. The interceptor may return a modified
   * response object or a `Promise` that resolves to one.
   *
   * @param {ResponseInterceptor} fn - The interceptor function to add.
   * @returns {this} The session instance, enabling a fluent call chain.
   */
  onResponse(fn: ResponseInterceptor): this {
    this.interceptors.addResponseInterceptor(fn);
    return this;
  }

  /**
   * Applies a token-bucket rate limit to all requests issued by this session.
   * Requests that exceed the configured rate will wait until a token becomes
   * available before proceeding.
   *
   * @param {RateLimitConfig} config - Rate limit parameters (`maxRequests` per `windowMs`).
   * @returns {this} The session instance, enabling a fluent call chain.
   */
  setRateLimit(config: RateLimitConfig): this {
    this.rateLimiter = new RateLimiter(config);
    return this;
  }

  /**
   * Issues a `GET` request and resolves with the complete response.
   *
   * @param {string}          url      - The URL to request.
   * @param {RequestOptions}  [options] - Optional per-request settings.
   * @returns {Promise<NLcURLResponse>} Resolves with the server response.
   */
  get(url: string, options?: RequestOptions): Promise<NLcURLResponse> {
    return this.request({ ...options, url, method: 'GET' });
  }

  /**
   * Issues a `POST` request and resolves with the complete response.
   *
   * @param {string}         url      - The URL to request.
   * @param {RequestBody}    [body]   - Request body payload.
   * @param {RequestOptions} [options] - Optional per-request settings.
   * @returns {Promise<NLcURLResponse>} Resolves with the server response.
   */
  post(url: string, body?: RequestBody, options?: RequestOptions): Promise<NLcURLResponse> {
    return this.request({ ...options, url, method: 'POST', body });
  }

  /**
   * Issues a `PUT` request and resolves with the complete response.
   *
   * @param {string}         url      - The URL to request.
   * @param {RequestBody}    [body]   - Request body payload.
   * @param {RequestOptions} [options] - Optional per-request settings.
   * @returns {Promise<NLcURLResponse>} Resolves with the server response.
   */
  put(url: string, body?: RequestBody, options?: RequestOptions): Promise<NLcURLResponse> {
    return this.request({ ...options, url, method: 'PUT', body });
  }

  /**
   * Issues a `PATCH` request and resolves with the complete response.
   *
   * @param {string}         url      - The URL to request.
   * @param {RequestBody}    [body]   - Request body payload.
   * @param {RequestOptions} [options] - Optional per-request settings.
   * @returns {Promise<NLcURLResponse>} Resolves with the server response.
   */
  patch(url: string, body?: RequestBody, options?: RequestOptions): Promise<NLcURLResponse> {
    return this.request({ ...options, url, method: 'PATCH', body });
  }

  /**
   * Issues a `DELETE` request and resolves with the complete response.
   *
   * @param {string}         url      - The URL to request.
   * @param {RequestOptions} [options] - Optional per-request settings.
   * @returns {Promise<NLcURLResponse>} Resolves with the server response.
   */
  delete(url: string, options?: RequestOptions): Promise<NLcURLResponse> {
    return this.request({ ...options, url, method: 'DELETE' });
  }

  /**
   * Issues a `HEAD` request and resolves with the complete response (no body).
   *
   * @param {string}         url      - The URL to request.
   * @param {RequestOptions} [options] - Optional per-request settings.
   * @returns {Promise<NLcURLResponse>} Resolves with the server response.
   */
  head(url: string, options?: RequestOptions): Promise<NLcURLResponse> {
    return this.request({ ...options, url, method: 'HEAD' });
  }

  /**
   * Issues an `OPTIONS` request and resolves with the complete response.
   *
   * @param {string}         url      - The URL to request.
   * @param {RequestOptions} [options] - Optional per-request settings.
   * @returns {Promise<NLcURLResponse>} Resolves with the server response.
   */
  options(url: string, options?: RequestOptions): Promise<NLcURLResponse> {
    return this.request({ ...options, url, method: 'OPTIONS' });
  }

  /**
   * Executes a fully described HTTP request, applying session defaults, request
   * interceptors, redirect following, cookie management, and response
   * interceptors in sequence.
   *
   * @param {NLcURLRequest} input - The request descriptor.
   * @returns {Promise<NLcURLResponse>} Resolves with the final response after all redirects.
   * @throws {NLcURLError}     If the session has been closed.
   * @throws {AbortError}      If the provided `AbortSignal` fires before completion.
   * @throws {TimeoutError}    If any configured timeout is exceeded.
   * @throws {ConnectionError} If a TCP connection cannot be established.
   * @throws {TLSError}        If the TLS handshake fails.
   * @throws {ProxyError}      If the proxy tunnel cannot be established.
   * @throws {NLcURLError}     If the maximum number of redirects is exceeded (`ERR_MAX_REDIRECTS`).
   */
  async request(input: NLcURLRequest): Promise<NLcURLResponse> {
    if (this.closed) {
      throw new NLcURLError('Session is closed', 'ERR_SESSION_CLOSED');
    }

    if (this.rateLimiter) {
      await this.rateLimiter.acquire();
    }

    let req = this.mergeDefaults(input);

    req = await this.interceptors.processRequest(req);

    const profile = this.resolveProfile(req);

    const negotiatorOptions: NegotiatorOptions = {
      stealth: req.stealth,
      profile,
      insecure: req.insecure,
    };

    const totalStart = Date.now();

    let response: NLcURLResponse;
    if (this.config.retry && this.config.retry.count && this.config.retry.count > 0) {
      response = await withRetry(
        {
          count: this.config.retry.count,
          delay: this.config.retry.delay ?? 1000,
          backoff: this.config.retry.backoff ?? 'exponential',
          jitter: this.config.retry.jitter ?? 200,
          retryOn: this.config.retry.retryOn,
        },
        () => this.executeWithRedirects(req, negotiatorOptions),
      );
    } else {
      response = await this.executeWithRedirects(req, negotiatorOptions);
    }

    if (response.timings) {
      (response.timings as RequestTimings).total = Date.now() - totalStart;
    }

    if (this.cookieJar) {
      const url = new URL(response.url);
      this.cookieJar.setCookies(response.headers, url, response.rawHeaders);
    }

    response = await this.interceptors.processResponse(response);

    return response;
  }

  /**
   * Returns the active {@link CookieJar} for this session, or `null` if
   * cookie management was disabled via `cookieJar: false`.
   *
   * @returns {CookieJar|null} The shared cookie jar, or `null`.
   */
  getCookies(): CookieJar | null {
    return this.cookieJar;
  }

  /**
   * Closes the session, releasing any pooled connections. After calling this
   * method, issuing further requests will throw an `NLcURLError` with code
   * `ERR_SESSION_CLOSED`. Subsequent calls are no-ops.
   */
  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.negotiator.close();
  }

  private mergeDefaults(input: NLcURLRequest): NLcURLRequest {
    const cfg = this.config;

    let url = input.url;
    if (cfg.baseURL && !url.startsWith('http://') && !url.startsWith('https://')) {
      url = resolveURL(cfg.baseURL, url);
    } else if (input.baseURL && !url.startsWith('http://') && !url.startsWith('https://')) {
      url = resolveURL(input.baseURL, url);
    }

    if (input.params) {
      url = appendParams(url, input.params);
    }

    const headers: Record<string, string> = {};
    if (cfg.headers) {
      for (const [k, v] of Object.entries(cfg.headers)) {
        headers[k.toLowerCase()] = v;
      }
    }
    if (input.headers) {
      for (const [k, v] of Object.entries(input.headers)) {
        headers[k.toLowerCase()] = v;
      }
    }

    if (this.cookieJar) {
      const parsedUrl = new URL(url);
      const cookieHeader = this.cookieJar.getCookieHeader(parsedUrl);
      if (cookieHeader) {
        const existing = headers['cookie'];
        headers['cookie'] = existing ? `${existing}; ${cookieHeader}` : cookieHeader;
      }
    }

    return {
      ...input,
      url,
      headers,
      method: input.method ?? 'GET',
      impersonate: input.impersonate ?? cfg.impersonate,
      ja3: input.ja3 ?? cfg.ja3,
      akamai: input.akamai ?? cfg.akamai,
      stealth: input.stealth ?? cfg.stealth,
      proxy: input.proxy ?? cfg.proxy,
      proxyAuth: input.proxyAuth ?? cfg.proxyAuth,
      followRedirects: input.followRedirects ?? cfg.followRedirects ?? true,
      maxRedirects: input.maxRedirects ?? cfg.maxRedirects ?? MAX_REDIRECTS,
      insecure: input.insecure ?? cfg.insecure ?? false,
      httpVersion: input.httpVersion ?? cfg.httpVersion,
      timeout: input.timeout ?? cfg.timeout,
      acceptEncoding: input.acceptEncoding ?? cfg.acceptEncoding,
      dnsFamily: input.dnsFamily ?? cfg.dnsFamily,
    };
  }

  private resolveProfile(req: NLcURLRequest): BrowserProfile | undefined {
    if (!req.impersonate) return undefined;
    const profile = getProfile(req.impersonate);
    if (!profile) {
      throw new NLcURLError(
        `Unknown browser profile: "${req.impersonate}"`,
        'ERR_UNKNOWN_PROFILE',
      );
    }
    return profile;
  }

  private async executeWithRedirects(
    req: NLcURLRequest,
    options: NegotiatorOptions,
  ): Promise<NLcURLResponse> {
    let currentReq = req;
    let redirectCount = 0;
    const maxRedirects = req.maxRedirects ?? MAX_REDIRECTS;
    const shouldFollow = req.followRedirects ?? true;

    while (true) {
      if (currentReq.signal?.aborted) {
        throw new AbortError();
      }

      const response = await this.negotiator.send(currentReq, options);

      const isRedirect = [301, 302, 303, 307, 308].includes(response.status);
      if (!isRedirect || !shouldFollow) {
        if (redirectCount > 0) {
          return new NLcURLResponse({
            status: response.status,
            statusText: response.statusText,
            headers: response.headers,
            rawHeaders: response.rawHeaders,
            rawBody: response.rawBody,
            httpVersion: response.httpVersion,
            url: currentReq.url,
            redirectCount,
            timings: response.timings,
            request: response.request,
          });
        }
        return response;
      }

      redirectCount++;
      if (redirectCount > maxRedirects) {
        throw new NLcURLError(
          `Maximum redirect limit (${maxRedirects}) exceeded`,
          'ERR_MAX_REDIRECTS',
        );
      }

      const location = response.headers['location'];
      if (!location) {
        return response;
      }

      let redirectUrl: string;
      try {
        redirectUrl = resolveURL(currentReq.url, location);
        const parsed = new URL(redirectUrl);
        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
          throw new NLcURLError(
            `Redirect to unsupported protocol: ${parsed.protocol}`,
            'ERR_INVALID_REDIRECT',
          );
        }
      } catch (err) {
        if (err instanceof NLcURLError) throw err;
        throw new NLcURLError(
          `Invalid redirect URL: ${location}`,
          'ERR_INVALID_REDIRECT',
        );
      }

      if (this.cookieJar) {
        const url = new URL(response.url);
        this.cookieJar.setCookies(response.headers, url, response.rawHeaders);
      }

      let method = currentReq.method ?? 'GET';
      let body = currentReq.body;

      if (response.status === 303) {
        method = 'GET';
        body = null;
      } else if (
        (response.status === 301 || response.status === 302) &&
        method === 'POST'
      ) {
        method = 'GET';
        body = null;
      }

      const headers = { ...currentReq.headers };
      delete headers['content-type'];
      delete headers['content-length'];

      if (this.cookieJar) {
        const parsedUrl = new URL(redirectUrl);
        const cookieHeader = this.cookieJar.getCookieHeader(parsedUrl);
        if (cookieHeader) {
          headers['cookie'] = cookieHeader;
        } else {
          delete headers['cookie'];
        }
      }

      const originalOrigin = new URL(currentReq.url).origin;
      const redirectOrigin = new URL(redirectUrl).origin;
      if (originalOrigin !== redirectOrigin) {
        delete headers['authorization'];
        delete headers['proxy-authorization'];
      }

      currentReq = {
        ...currentReq,
        url: redirectUrl,
        method,
        body,
        headers,
      };
    }
  }
}
