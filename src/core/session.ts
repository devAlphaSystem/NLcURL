import type { NLcURLRequest, NLcURLSessionConfig, HttpMethod, RetryConfig, RequestBody, TimeoutConfig, RequestTimings, ProgressCallback } from "./request.js";
import { NLcURLResponse } from "./response.js";
import { AbortError, HTTPError, NLcURLError } from "./errors.js";
import { ProtocolNegotiator, type NegotiatorOptions } from "../http/negotiator.js";
import { CookieJar } from "../cookies/jar.js";
import { InterceptorChain, type RequestInterceptor, type ResponseInterceptor } from "../middleware/interceptor.js";
import { RateLimiter, type RateLimitConfig } from "../middleware/rate-limiter.js";
import { withRetry } from "../middleware/retry.js";
import { getProfile, DEFAULT_PROFILE, type BrowserProfile } from "../fingerprints/database.js";
import { resolveURL, appendParams } from "../utils/url.js";
import { type Logger, getDefaultLogger } from "../utils/logger.js";
import { validateSessionConfig, validateRequest, validateRateLimitConfig, validateHeaderName, validateHeaderValue } from "./validation.js";
import { resolveEnvProxy } from "../proxy/env-proxy.js";
import { CacheStore } from "../cache/store.js";
import { HSTSStore } from "../hsts/store.js";
import type { CacheMode } from "../cache/types.js";

const MAX_REDIRECTS = 20;

/**
 * Request options that can be passed alongside a URL and HTTP method. All
 * fields from {@link NLcURLRequest} except `url`, `method`, and `body`.
 *
 * @typedef {Omit<NLcURLRequest, 'url'|'method'|'body'>} RequestOptions
 */
export type RequestOptions = Omit<NLcURLRequest, "url" | "method" | "body">;

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
  private readonly logger: Logger;
  private rateLimiter: RateLimiter | null = null;
  private readonly cacheStore: CacheStore | null;
  private readonly hstsStore: HSTSStore | null;
  private closed = false;

  /**
   * Creates a new NLcURLSession.
   *
   * @param {NLcURLSessionConfig} [config={}] - Session-level defaults applied to every request.
   */
  constructor(config: NLcURLSessionConfig = {}) {
    validateSessionConfig(config as Record<string, unknown>);
    this.config = config;
    this.negotiator = new ProtocolNegotiator(undefined, config.dns);
    this.interceptors = new InterceptorChain();
    this.logger = config.logger ?? getDefaultLogger();

    if (config.cookieJar === true || config.cookieJar === undefined) {
      this.cookieJar = new CookieJar();
    } else if (config.cookieJar === false) {
      this.cookieJar = null;
    } else if (config.cookieJar instanceof CookieJar) {
      this.cookieJar = config.cookieJar;
    } else {
      this.cookieJar = new CookieJar();
    }

    if (config.cacheConfig && config.cacheConfig.enabled !== false) {
      this.cacheStore = new CacheStore(config.cacheConfig);
    } else {
      this.cacheStore = null;
    }

    if (config.hsts && config.hsts.enabled !== false) {
      this.hstsStore = new HSTSStore(config.hsts);
    } else {
      this.hstsStore = null;
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
    validateRateLimitConfig(config as unknown as Record<string, unknown>);
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
    return this.request({ ...options, url, method: "GET" });
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
    return this.request({ ...options, url, method: "POST", body });
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
    return this.request({ ...options, url, method: "PUT", body });
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
    return this.request({ ...options, url, method: "PATCH", body });
  }

  /**
   * Issues a `DELETE` request and resolves with the complete response.
   *
   * @param {string}         url      - The URL to request.
   * @param {RequestOptions} [options] - Optional per-request settings.
   * @returns {Promise<NLcURLResponse>} Resolves with the server response.
   */
  delete(url: string, options?: RequestOptions): Promise<NLcURLResponse> {
    return this.request({ ...options, url, method: "DELETE" });
  }

  /**
   * Issues a `HEAD` request and resolves with the complete response (no body).
   *
   * @param {string}         url      - The URL to request.
   * @param {RequestOptions} [options] - Optional per-request settings.
   * @returns {Promise<NLcURLResponse>} Resolves with the server response.
   */
  head(url: string, options?: RequestOptions): Promise<NLcURLResponse> {
    return this.request({ ...options, url, method: "HEAD" });
  }

  /**
   * Issues an `OPTIONS` request and resolves with the complete response.
   *
   * @param {string}         url      - The URL to request.
   * @param {RequestOptions} [options] - Optional per-request settings.
   * @returns {Promise<NLcURLResponse>} Resolves with the server response.
   */
  options(url: string, options?: RequestOptions): Promise<NLcURLResponse> {
    return this.request({ ...options, url, method: "OPTIONS" });
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
      throw new NLcURLError("Session is closed", "ERR_SESSION_CLOSED");
    }

    validateRequest(input as unknown as Record<string, unknown>);

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
      tls: req.tls,
      dns: req.dns ?? this.config.dns,
      ech: req.ech ?? this.config.ech,
      altSvc: this.config.altSvc,
    };

    const totalStart = Date.now();

    this.logger.debug(`request ${req.method} ${req.url}`);

    const cacheMode: CacheMode | undefined = req.cache;
    let cacheEval: ReturnType<CacheStore["evaluate"]> | undefined;

    if (this.cacheStore) {
      cacheEval = this.cacheStore.evaluate(req, cacheMode);

      if (cacheEval.serveCached) {
        this.logger.debug(`cache hit (fresh) ${req.method} ${req.url}`);
        const cached = this.cacheStore.responseFromEntry(cacheEval.serveCached, req);
        return this.interceptors.processResponse(cached);
      }

      if (cacheMode === "only-if-cached" && !cacheEval.matchedEntry) {
        return new NLcURLResponse({
          status: 504,
          statusText: "Gateway Timeout",
          headers: {},
          rawBody: Buffer.alloc(0),
          httpVersion: "HTTP/1.1",
          url: req.url,
          redirectCount: 0,
          timings: { dns: 0, connect: 0, tls: 0, firstByte: 0, total: 0 },
          request: { url: req.url, method: (req.method ?? "GET") as "GET", headers: req.headers ?? {} },
        });
      }

      if (cacheEval.conditionalHeaders) {
        req = { ...req, headers: { ...req.headers, ...cacheEval.conditionalHeaders } };
      }
    }

    let response: NLcURLResponse;
    if (this.config.retry && this.config.retry.count && this.config.retry.count > 0) {
      response = await withRetry(
        {
          count: this.config.retry.count,
          delay: this.config.retry.delay ?? 1000,
          backoff: this.config.retry.backoff ?? "exponential",
          jitter: this.config.retry.jitter ?? 200,
          retryOn: this.config.retry.retryOn,
        },
        () => this.executeWithRedirects(req, negotiatorOptions),
        this.logger,
      );
    } else {
      response = await this.executeWithRedirects(req, negotiatorOptions);
    }

    if (response.timings) {
      (response.timings as RequestTimings).total = Date.now() - totalStart;
    }

    if (this.hstsStore) {
      const stsHeader = response.headers["strict-transport-security"];
      if (stsHeader) {
        const responseUrl = new URL(response.url);
        this.hstsStore.parseHeader(responseUrl.hostname, stsHeader, responseUrl.protocol === "https:");
      }
    }

    if (this.cacheStore && response.status === 304 && cacheEval?.matchedEntry) {
      this.logger.debug(`cache revalidation 304 ${req.method} ${req.url}`);
      response = this.cacheStore.mergeNotModified(cacheEval.matchedEntry, response);
    } else if (this.cacheStore && cacheEval?.shouldStore && cacheMode !== "no-store") {
      this.cacheStore.store(req, response);
    }

    if (this.cookieJar) {
      const url = new URL(response.url);
      this.cookieJar.setCookies(response.headers, url, response.rawHeaders);
    }

    response = await this.interceptors.processResponse(response);

    this.logger.debug(`response ${req.method} ${req.url} ${response.status} ${response.timings?.total ?? Date.now() - totalStart}ms`);

    const shouldThrow = req.throwOnError ?? this.config.throwOnError;
    if (shouldThrow && !response.ok) {
      throw new HTTPError(`Request failed with status ${response.status}`, response.status);
    }

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
   * Returns the active {@link CacheStore} for this session, or `null` if
   * caching was not enabled.
   *
   * @returns {CacheStore|null} The cache store, or `null`.
   */
  getCache(): CacheStore | null {
    return this.cacheStore;
  }

  /**
   * Returns the active {@link HSTSStore} for this session, or `null` if
   * HSTS was not enabled.
   *
   * @returns {HSTSStore|null} The HSTS store, or `null`.
   */
  getHSTS(): HSTSStore | null {
    return this.hstsStore;
  }

  /**
   * Returns the Alt-Svc store used by this session's negotiator.
   * The store records Alt-Svc headers from responses for HTTP/3 discovery.
   */
  getAltSvc(): import("../http/alt-svc.js").AltSvcStore {
    return this.negotiator.altSvcStore;
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
    if (cfg.baseURL && !url.startsWith("http://") && !url.startsWith("https://")) {
      url = resolveURL(cfg.baseURL, url);
    } else if (input.baseURL && !url.startsWith("http://") && !url.startsWith("https://")) {
      url = resolveURL(input.baseURL, url);
    }

    if (input.params) {
      url = appendParams(url, input.params);
    }

    if (this.hstsStore) {
      url = this.hstsStore.upgradeURL(url);
    }

    const headers: Record<string, string> = {};
    if (cfg.headers) {
      for (const [k, v] of Object.entries(cfg.headers)) {
        validateHeaderName(k);
        validateHeaderValue(k, v);
        headers[k.toLowerCase()] = v;
      }
    }
    if (input.headers) {
      for (const [k, v] of Object.entries(input.headers)) {
        validateHeaderName(k);
        validateHeaderValue(k, v);
        headers[k.toLowerCase()] = v;
      }
    }

    if (input.range && !headers["range"]) {
      headers["range"] = input.range;
    }

    if (this.cookieJar) {
      const parsedUrl = new URL(url);
      const cookieHeader = this.cookieJar.getCookieHeader(parsedUrl);
      if (cookieHeader) {
        const existing = headers["cookie"];
        headers["cookie"] = existing ? `${existing}; ${cookieHeader}` : cookieHeader;
      }
    }

    return {
      ...input,
      url,
      headers,
      method: input.method ?? "GET",
      impersonate: input.impersonate ?? cfg.impersonate,
      ja3: input.ja3 ?? cfg.ja3,
      akamai: input.akamai ?? cfg.akamai,
      stealth: input.stealth ?? cfg.stealth,
      proxy: input.proxy ?? cfg.proxy ?? resolveEnvProxy(url),
      proxyAuth: input.proxyAuth ?? cfg.proxyAuth,
      followRedirects: input.followRedirects ?? cfg.followRedirects ?? true,
      maxRedirects: input.maxRedirects ?? cfg.maxRedirects ?? MAX_REDIRECTS,
      insecure: input.insecure ?? cfg.insecure ?? false,
      httpVersion: input.httpVersion ?? cfg.httpVersion,
      timeout: input.timeout ?? cfg.timeout,
      acceptEncoding: input.acceptEncoding ?? cfg.acceptEncoding,
      dnsFamily: input.dnsFamily ?? cfg.dnsFamily,
      tls: input.tls ?? cfg.tls,
      throwOnError: input.throwOnError ?? cfg.throwOnError,
      onUploadProgress: input.onUploadProgress,
      onDownloadProgress: input.onDownloadProgress,
    };
  }

  private resolveProfile(req: NLcURLRequest): BrowserProfile | undefined {
    if (!req.impersonate) return undefined;
    const profile = getProfile(req.impersonate);
    if (!profile) {
      throw new NLcURLError(`Unknown browser profile: "${req.impersonate}"`, "ERR_UNKNOWN_PROFILE");
    }
    return profile;
  }

  private async executeWithRedirects(req: NLcURLRequest, options: NegotiatorOptions): Promise<NLcURLResponse> {
    let currentReq = req;
    let redirectCount = 0;
    const maxRedirects = req.maxRedirects ?? MAX_REDIRECTS;
    const shouldFollow = req.followRedirects ?? true;

    while (true) {
      if (currentReq.signal?.aborted) {
        throw new AbortError();
      }

      let response: NLcURLResponse;
      if (currentReq.signal) {
        const sig = currentReq.signal;
        response = await new Promise<NLcURLResponse>((resolve, reject) => {
          const onAbort = () => reject(new AbortError());
          sig.addEventListener("abort", onAbort, { once: true });
          this.negotiator.send(currentReq, options).then(
            (res) => {
              sig.removeEventListener("abort", onAbort);
              resolve(res);
            },
            (err) => {
              sig.removeEventListener("abort", onAbort);
              reject(err);
            },
          );
        });
      } else {
        response = await this.negotiator.send(currentReq, options);
      }

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
        throw new NLcURLError(`Maximum redirect limit (${maxRedirects}) exceeded`, "ERR_MAX_REDIRECTS");
      }

      const location = response.headers["location"];
      if (!location) {
        return response;
      }

      this.logger.debug(`redirect ${response.status} -> ${location}`);

      let redirectUrl: string;
      try {
        redirectUrl = resolveURL(currentReq.url, location);
        const parsed = new URL(redirectUrl);
        if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
          throw new NLcURLError(`Redirect to unsupported protocol: ${parsed.protocol}`, "ERR_INVALID_REDIRECT");
        }
      } catch (err) {
        if (err instanceof NLcURLError) throw err;
        throw new NLcURLError(`Invalid redirect URL: ${location}`, "ERR_INVALID_REDIRECT");
      }

      if (this.cookieJar) {
        const url = new URL(response.url);
        this.cookieJar.setCookies(response.headers, url, response.rawHeaders);
      }

      let method = currentReq.method ?? "GET";
      let body = currentReq.body;

      if (response.status === 303) {
        method = "GET";
        body = null;
      } else if ((response.status === 301 || response.status === 302) && method === "POST") {
        method = "GET";
        body = null;
      }

      const headers = { ...currentReq.headers };
      if (body === null) {
        delete headers["content-type"];
        delete headers["content-length"];
      }

      if (this.cookieJar) {
        const parsedUrl = new URL(redirectUrl);
        const cookieHeader = this.cookieJar.getCookieHeader(parsedUrl);
        if (cookieHeader) {
          headers["cookie"] = cookieHeader;
        } else {
          delete headers["cookie"];
        }
      }

      const originalOrigin = new URL(currentReq.url).origin;
      const redirectOrigin = new URL(redirectUrl).origin;
      if (originalOrigin !== redirectOrigin) {
        delete headers["authorization"];
        delete headers["proxy-authorization"];
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
