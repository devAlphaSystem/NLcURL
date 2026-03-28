import type { NLcURLRequest, NLcURLSessionConfig, RequestBody } from "./request.js";
import { NLcURLResponse } from "./response.js";
import { AbortError, HTTPError, NLcURLError } from "./errors.js";
import { ProtocolNegotiator, type NegotiatorOptions } from "../http/negotiator.js";
import { CookieJar } from "../cookies/jar.js";
import { InterceptorChain, type RequestInterceptor, type ResponseInterceptor } from "../middleware/interceptor.js";
import { RateLimiter, type RateLimitConfig } from "../middleware/rate-limiter.js";
import { withRetry } from "../middleware/retry.js";
import { getProfile, type BrowserProfile } from "../fingerprints/database.js";
import { resolveURL, appendParams } from "../utils/url.js";
import { type Logger, getDefaultLogger } from "../utils/logger.js";
import { validateSessionConfig, validateRequest, validateRateLimitConfig, validateHeaderName, validateHeaderValue, validateUrlSafety } from "./validation.js";
import { resolveEnvProxy } from "../proxy/env-proxy.js";
import { CacheStore } from "../cache/store.js";
import { HSTSStore } from "../hsts/store.js";
import type { CacheMode } from "../cache/types.js";
import { buildAuthHeader } from "./auth.js";
import { compressBody, shouldCompress } from "../utils/compression.js";
import { computeReferrer, parseReferrerPolicy, type ReferrerPolicy } from "../http/referrer-policy.js";
import { verifyIntegrity } from "../utils/integrity.js";

const MAX_REDIRECTS = 20;

/**
 * Request options excluding URL, method, and body — used for convenience method signatures.
 */
export type RequestOptions = Omit<NLcURLRequest, "url" | "method" | "body">;

/**
 * Manages a persistent HTTP session with connection pooling, cookie storage,
 * caching, HSTS enforcement, interceptors, rate limiting, and retry logic.
 *
 * @class
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
   * Creates a new session with the given configuration.
   *
   * @param {NLcURLSessionConfig} [config={}] - Session-level defaults and feature toggles.
   * @throws {NLcURLError} If configuration values are invalid.
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
   * Registers a request interceptor invoked before each outgoing request.
   *
   * @param {RequestInterceptor} fn - The interceptor function.
   * @returns {this} The session instance for chaining.
   */
  onRequest(fn: RequestInterceptor): this {
    this.interceptors.addRequestInterceptor(fn);
    return this;
  }

  /**
   * Registers a response interceptor invoked after each incoming response.
   *
   * @param {ResponseInterceptor} fn - The interceptor function.
   * @returns {this} The session instance for chaining.
   */
  onResponse(fn: ResponseInterceptor): this {
    this.interceptors.addResponseInterceptor(fn);
    return this;
  }

  /**
   * Configures a token-bucket rate limiter for this session.
   *
   * @param {RateLimitConfig} config - Rate limit parameters.
   * @returns {this} The session instance for chaining.
   * @throws {NLcURLError} If the rate limit config is invalid.
   */
  setRateLimit(config: RateLimitConfig): this {
    validateRateLimitConfig(config as unknown as Record<string, unknown>);
    this.rateLimiter = new RateLimiter(config);
    return this;
  }

  /**
   * Sends an HTTP GET request.
   *
   * @param {string} url - The target URL.
   * @param {RequestOptions} [options] - Additional request options.
   * @returns {Promise<NLcURLResponse>} Resolves with the server response.
   */
  get(url: string, options?: RequestOptions): Promise<NLcURLResponse> {
    return this.request({ ...options, url, method: "GET" });
  }

  /**
   * Sends an HTTP POST request.
   *
   * @param {string} url - The target URL.
   * @param {RequestBody} [body] - The request body.
   * @param {RequestOptions} [options] - Additional request options.
   * @returns {Promise<NLcURLResponse>} Resolves with the server response.
   */
  post(url: string, body?: RequestBody, options?: RequestOptions): Promise<NLcURLResponse> {
    return this.request({ ...options, url, method: "POST", body });
  }

  /**
   * Sends an HTTP PUT request.
   *
   * @param {string} url - The target URL.
   * @param {RequestBody} [body] - The request body.
   * @param {RequestOptions} [options] - Additional request options.
   * @returns {Promise<NLcURLResponse>} Resolves with the server response.
   */
  put(url: string, body?: RequestBody, options?: RequestOptions): Promise<NLcURLResponse> {
    return this.request({ ...options, url, method: "PUT", body });
  }

  /**
   * Sends an HTTP PATCH request.
   *
   * @param {string} url - The target URL.
   * @param {RequestBody} [body] - The request body.
   * @param {RequestOptions} [options] - Additional request options.
   * @returns {Promise<NLcURLResponse>} Resolves with the server response.
   */
  patch(url: string, body?: RequestBody, options?: RequestOptions): Promise<NLcURLResponse> {
    return this.request({ ...options, url, method: "PATCH", body });
  }

  /**
   * Sends an HTTP DELETE request.
   *
   * @param {string} url - The target URL.
   * @param {RequestOptions} [options] - Additional request options.
   * @returns {Promise<NLcURLResponse>} Resolves with the server response.
   */
  delete(url: string, options?: RequestOptions): Promise<NLcURLResponse> {
    return this.request({ ...options, url, method: "DELETE" });
  }

  /**
   * Sends an HTTP HEAD request.
   *
   * @param {string} url - The target URL.
   * @param {RequestOptions} [options] - Additional request options.
   * @returns {Promise<NLcURLResponse>} Resolves with the server response.
   */
  head(url: string, options?: RequestOptions): Promise<NLcURLResponse> {
    return this.request({ ...options, url, method: "HEAD" });
  }

  /**
   * Sends an HTTP OPTIONS request.
   *
   * @param {string} url - The target URL.
   * @param {RequestOptions} [options] - Additional request options.
   * @returns {Promise<NLcURLResponse>} Resolves with the server response.
   */
  options(url: string, options?: RequestOptions): Promise<NLcURLResponse> {
    return this.request({ ...options, url, method: "OPTIONS" });
  }

  /**
   * Sends an HTTP QUERY request (RFC 9110).
   *
   * @param {string} url - The target URL.
   * @param {RequestBody} [body] - The query body.
   * @param {RequestOptions} [options] - Additional request options.
   * @returns {Promise<NLcURLResponse>} Resolves with the server response.
   */
  query(url: string, body?: RequestBody, options?: RequestOptions): Promise<NLcURLResponse> {
    return this.request({ ...options, url, method: "QUERY", body });
  }

  /**
   * Sends an HTTP request with full session features including caching,
   * HSTS upgrade, cookie handling, compression, retry, and interceptors.
   *
   * @param {NLcURLRequest} input - The complete request descriptor.
   * @returns {Promise<NLcURLResponse>} Resolves with the server response.
   * @throws {NLcURLError} If the session is closed.
   * @throws {HTTPError} If `throwOnError` is enabled and the response is non-2xx.
   */
  async request(input: NLcURLRequest): Promise<NLcURLResponse> {
    if (this.closed) {
      throw new NLcURLError("Session is closed", "ERR_SESSION_CLOSED");
    }

    validateRequest(input as unknown as Record<string, unknown>);

    const blockPrivateIPs = input.blockPrivateIPs ?? this.config.blockPrivateIPs;
    const blockDangerousPorts = input.blockDangerousPorts ?? this.config.blockDangerousPorts;
    if (blockPrivateIPs || blockDangerousPorts) {
      validateUrlSafety(input.url, {
        allowPrivateIPs: !blockPrivateIPs,
        allowDangerousPorts: !blockDangerousPorts,
      });
    }

    if (this.rateLimiter) {
      await this.rateLimiter.acquire();
    }

    let req = this.mergeDefaults(input);

    req = await this.interceptors.processRequest(req);

    const compressionEncoding = req.compressBody ?? this.config.compressBody;
    if (compressionEncoding && req.body) {
      let bodyBuf: Buffer | null = null;
      if (Buffer.isBuffer(req.body)) {
        bodyBuf = req.body;
      } else if (typeof req.body === "string") {
        bodyBuf = Buffer.from(req.body, "utf-8");
      }
      if (bodyBuf && shouldCompress(bodyBuf.length)) {
        const compressed = await compressBody(bodyBuf, compressionEncoding);
        const headers = { ...req.headers };
        headers["content-encoding"] = compressionEncoding === "br" ? "br" : compressionEncoding;
        headers["content-length"] = String(compressed.length);
        req = { ...req, body: compressed, headers };
      }
    }

    if (req.methodOverride === "QUERY") {
      const headers = { ...req.headers };
      headers["x-http-method-override"] = "QUERY";
      req = { ...req, method: "POST", headers };
    }

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

    const authConfig = req.auth ?? this.config.auth;
    if (response.status === 401 && authConfig?.type === "digest" && response.headers["www-authenticate"]) {
      const authHeader = buildAuthHeader(authConfig, {
        method: req.method ?? "GET",
        url: req.url,
        wwwAuthenticate: response.headers["www-authenticate"],
        headers: req.headers as Record<string, string>,
      });
      if (authHeader) {
        const retryReq = { ...req, headers: { ...req.headers, authorization: authHeader } };
        response = await this.executeWithRedirects(retryReq, negotiatorOptions);
      }
    }

    if (response.timings) {
      response.timings.total = Date.now() - totalStart;
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

    const integrityHash = req.integrity;
    if (integrityHash && response.rawBody.length > 0) {
      if (!verifyIntegrity(response.rawBody, integrityHash)) {
        throw new NLcURLError("Response body integrity check failed", "ERR_INTEGRITY_MISMATCH");
      }
    }

    const maxResponseSize = req.maxResponseSize ?? this.config.maxResponseSize;
    if (maxResponseSize !== undefined && response.rawBody.length > maxResponseSize) {
      throw new NLcURLError(`Response body size (${response.rawBody.length}) exceeds maxResponseSize (${maxResponseSize})`, "ERR_BODY_TOO_LARGE");
    }

    const shouldThrow = req.throwOnError ?? this.config.throwOnError;
    if (shouldThrow && !response.ok) {
      throw new HTTPError(`Request failed with status ${response.status}`, response.status);
    }

    return response;
  }

  /**
   * Returns the session's cookie jar, or `null` if cookies are disabled.
   *
   * @returns {CookieJar|null} The cookie jar instance.
   */
  getCookies(): CookieJar | null {
    return this.cookieJar;
  }

  /**
   * Returns the session's cache store, or `null` if caching is disabled.
   *
   * @returns {CacheStore|null} The cache store instance.
   */
  getCache(): CacheStore | null {
    return this.cacheStore;
  }

  /**
   * Returns the session's HSTS store, or `null` if HSTS is disabled.
   *
   * @returns {HSTSStore|null} The HSTS store instance.
   */
  getHSTS(): HSTSStore | null {
    return this.hstsStore;
  }

  /**
   * Returns the session's Alt-Svc store for HTTP alternative service lookups.
   *
   * @returns {import("../http/alt-svc.js").AltSvcStore} The Alt-Svc store instance.
   */
  getAltSvc(): import("../http/alt-svc.js").AltSvcStore {
    return this.negotiator.altSvcStore;
  }

  /**
   * Closes the session and releases all pooled connections.
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

    const authConfig = input.auth ?? cfg.auth;
    if (authConfig && !headers["authorization"]) {
      const authHeader = buildAuthHeader(authConfig, {
        method: input.method ?? "GET",
        url,
        headers,
      });
      if (authHeader) {
        headers["authorization"] = authHeader;
      }
    }

    if (input.expect100Continue && input.body && !headers["expect"]) {
      headers["expect"] = "100-continue";
    }

    if (this.cookieJar) {
      const parsedUrl = new URL(url);
      const cookieHeader = this.cookieJar.getCookieHeader(parsedUrl);
      if (cookieHeader) {
        const existing = headers["cookie"];
        headers["cookie"] = existing ? `${existing}; ${cookieHeader}` : cookieHeader;
      }

      const xsrfCookieName = cfg.xsrfCookieName;
      const xsrfHeaderName = cfg.xsrfHeaderName ?? "X-XSRF-TOKEN";
      if (xsrfCookieName && !headers[xsrfHeaderName.toLowerCase()] && parsedUrl.protocol === "https:") {
        const allCookies = this.cookieJar.all({ includeHttpOnly: true });
        const xsrfCookie = allCookies.find((c) => c.name === xsrfCookieName);
        if (xsrfCookie) {
          headers[xsrfHeaderName.toLowerCase()] = xsrfCookie.value;
        }
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
    const visitedUrls = new Set<string>([req.url]);

    while (true) {
      if (currentReq.signal?.aborted) {
        throw new AbortError();
      }

      let response: NLcURLResponse;
      if (currentReq.signal) {
        const sig = currentReq.signal;
        response = await new Promise<NLcURLResponse>((resolve, reject) => {
          const onAbort = () => {
            reject(new AbortError());
          };
          sig.addEventListener("abort", onAbort, { once: true });
          this.negotiator.send(currentReq, options).then(
            (res) => {
              sig.removeEventListener("abort", onAbort);
              resolve(res);
            },
            (err: unknown) => {
              sig.removeEventListener("abort", onAbort);
              reject(err instanceof Error ? err : new NLcURLError(String(err), "ERR_UNKNOWN"));
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
            body: response.body,
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

      if (response.rawHeaders) {
        const locationValues = response.rawHeaders.filter(([k]) => k.toLowerCase() === "location").map(([, v]) => v);
        if (locationValues.length > 1) {
          const unique = new Set(locationValues);
          if (unique.size > 1) {
            throw new NLcURLError(`Ambiguous redirect: ${locationValues.length} conflicting Location headers`, "ERR_AMBIGUOUS_REDIRECT");
          }
        }
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

      const blockPrivateIPs = currentReq.blockPrivateIPs ?? this.config.blockPrivateIPs;
      const blockDangerousPorts = currentReq.blockDangerousPorts ?? this.config.blockDangerousPorts;
      if (blockPrivateIPs || blockDangerousPorts) {
        validateUrlSafety(redirectUrl, {
          allowPrivateIPs: !blockPrivateIPs,
          allowDangerousPorts: !blockDangerousPorts,
        });
      }

      if (visitedUrls.has(redirectUrl)) {
        throw new NLcURLError(`Redirect loop detected: ${redirectUrl}`, "ERR_REDIRECT_LOOP");
      }
      visitedUrls.add(redirectUrl);

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

      const originalParsed = new URL(currentReq.url);
      const redirectParsed = new URL(redirectUrl);

      if (originalParsed.protocol === "https:" && redirectParsed.protocol === "http:") {
        delete headers["authorization"];
        delete headers["proxy-authorization"];
        delete headers["cookie"];
        this.logger.warn(`Stripping sensitive headers on HTTPS→HTTP downgrade redirect to ${redirectUrl}`);
      }

      const originalOrigin = originalParsed.origin;
      const redirectOrigin = redirectParsed.origin;
      if (originalOrigin !== redirectOrigin) {
        delete headers["authorization"];
        delete headers["proxy-authorization"];
      }

      const refPolicy: ReferrerPolicy = (currentReq.referrerPolicy ?? this.config.referrerPolicy ?? "strict-origin-when-cross-origin") as ReferrerPolicy;
      const serverPolicy = response.headers["referrer-policy"];
      const effectivePolicy = serverPolicy ? (parseReferrerPolicy(serverPolicy) ?? refPolicy) : refPolicy;
      const referer = computeReferrer(originalParsed, redirectParsed, effectivePolicy);
      if (referer) {
        headers["referer"] = referer;
      } else {
        delete headers["referer"];
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
