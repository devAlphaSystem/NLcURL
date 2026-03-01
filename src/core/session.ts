/**
 * NLcURL Session.
 *
 * A persistent session that maintains cookies, connection pools,
 * default configuration, and middleware across multiple requests.
 */

import type {
  NLcURLRequest,
  NLcURLSessionConfig,
  HttpMethod,
  RetryConfig,
  RequestBody,
  TimeoutConfig,
} from './request.js';
import { NLcURLResponse } from './response.js';
import { AbortError, NLcURLError } from './errors.js';
import { ProtocolNegotiator, type NegotiatorOptions } from '../http/negotiator.js';
import { CookieJar } from '../cookies/jar.js';
import { InterceptorChain, type RequestInterceptor, type ResponseInterceptor } from '../middleware/interceptor.js';
import { RateLimiter, type RateLimitConfig } from '../middleware/rate-limiter.js';
import { getProfile, DEFAULT_PROFILE, type BrowserProfile } from '../fingerprints/database.js';
import { resolveURL, appendParams } from '../utils/url.js';

const MAX_REDIRECTS = 20;

/**
 * Convenience options for HTTP method shortcuts.
 */
export type RequestOptions = Omit<NLcURLRequest, 'url' | 'method' | 'body'>;

export class NLcURLSession {
  private readonly config: NLcURLSessionConfig;
  private readonly negotiator: ProtocolNegotiator;
  private readonly cookieJar: CookieJar | null;
  private readonly interceptors: InterceptorChain;
  private rateLimiter: RateLimiter | null = null;
  private closed = false;

  constructor(config: NLcURLSessionConfig = {}) {
    this.config = config;
    this.negotiator = new ProtocolNegotiator();
    this.interceptors = new InterceptorChain();

    // Cookie jar: true = create internal jar, string = unsupported (reserved)
    if (config.cookieJar === true || config.cookieJar === undefined) {
      this.cookieJar = new CookieJar();
    } else if (config.cookieJar === false) {
      this.cookieJar = null;
    } else {
      this.cookieJar = new CookieJar();
    }
  }

  // ---- Middleware registration ----

  /**
   * Register a request interceptor.
   *
   * Interceptors run before dispatch and may modify the outgoing request.
   */
  onRequest(fn: RequestInterceptor): this {
    this.interceptors.addRequestInterceptor(fn);
    return this;
  }

  /**
   * Register a response interceptor.
   *
   * Interceptors run after a response is received and may transform it.
   */
  onResponse(fn: ResponseInterceptor): this {
    this.interceptors.addResponseInterceptor(fn);
    return this;
  }

  /**
   * Enable per-session rate limiting.
   */
  setRateLimit(config: RateLimitConfig): this {
    this.rateLimiter = new RateLimiter(config);
    return this;
  }

  // ---- HTTP method shortcuts ----

  get(url: string, options?: RequestOptions): Promise<NLcURLResponse> {
    return this.request({ ...options, url, method: 'GET' });
  }

  post(url: string, body?: RequestBody, options?: RequestOptions): Promise<NLcURLResponse> {
    return this.request({ ...options, url, method: 'POST', body });
  }

  put(url: string, body?: RequestBody, options?: RequestOptions): Promise<NLcURLResponse> {
    return this.request({ ...options, url, method: 'PUT', body });
  }

  patch(url: string, body?: RequestBody, options?: RequestOptions): Promise<NLcURLResponse> {
    return this.request({ ...options, url, method: 'PATCH', body });
  }

  delete(url: string, options?: RequestOptions): Promise<NLcURLResponse> {
    return this.request({ ...options, url, method: 'DELETE' });
  }

  head(url: string, options?: RequestOptions): Promise<NLcURLResponse> {
    return this.request({ ...options, url, method: 'HEAD' });
  }

  options(url: string, options?: RequestOptions): Promise<NLcURLResponse> {
    return this.request({ ...options, url, method: 'OPTIONS' });
  }

  // ---- Core request method ----

  async request(input: NLcURLRequest): Promise<NLcURLResponse> {
    if (this.closed) {
      throw new NLcURLError('Session is closed', 'ERR_SESSION_CLOSED');
    }

    // Rate limiting
    if (this.rateLimiter) {
      await this.rateLimiter.acquire();
    }

    // Merge session defaults with per-request options
    let req = this.mergeDefaults(input);

    // Run request interceptors
    req = await this.interceptors.processRequest(req);

    // Resolve the profile
    const profile = this.resolveProfile(req);

    // Build negotiator options
    const negotiatorOptions: NegotiatorOptions = {
      stealth: req.stealth,
      profile,
      insecure: req.insecure,
    };

    // Execute with redirect following
    let response = await this.executeWithRedirects(req, negotiatorOptions);

    // Store cookies from response
    if (this.cookieJar) {
      const url = new URL(response.url);
      this.cookieJar.setCookies(response.headers, url, response.rawHeaders);
    }

    // Run response interceptors
    response = await this.interceptors.processResponse(response);

    return response;
  }

  // ---- Cookie access ----

  /**
   * Return the session cookie jar, or `null` when cookie management is disabled.
   */
  getCookies(): CookieJar | null {
    return this.cookieJar;
  }

  // ---- Lifecycle ----

  /**
   * Close the session and release pooled connections.
   */
  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.negotiator.close();
  }

  // ---- Internal helpers ----

  private mergeDefaults(input: NLcURLRequest): NLcURLRequest {
    const cfg = this.config;

    // Resolve base URL
    let url = input.url;
    if (cfg.baseURL && !url.startsWith('http://') && !url.startsWith('https://')) {
      url = resolveURL(cfg.baseURL, url);
    } else if (input.baseURL && !url.startsWith('http://') && !url.startsWith('https://')) {
      url = resolveURL(input.baseURL, url);
    }

    // Append query params
    if (input.params) {
      url = appendParams(url, input.params);
    }

    // Merge headers (session defaults first, request headers override)
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

    // Inject cookies
    if (this.cookieJar) {
      const parsedUrl = new URL(url);
      const cookieHeader = this.cookieJar.getCookieHeader(parsedUrl);
      if (cookieHeader) {
        // Merge with any explicitly set cookie header
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
      // Check abort signal
      if (currentReq.signal?.aborted) {
        throw new AbortError();
      }

      const response = await this.negotiator.send(currentReq, options);

      // Check if we should follow a redirect
      const isRedirect = [301, 302, 303, 307, 308].includes(response.status);
      if (!isRedirect || !shouldFollow) {
        // Attach redirect tracking to the final response
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

      // Extract Location header
      const location = response.headers['location'];
      if (!location) {
        return response;
      }

      // Resolve redirect URL and validate protocol
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

      // Store cookies from redirect response
      if (this.cookieJar) {
        const url = new URL(response.url);
        this.cookieJar.setCookies(response.headers, url, response.rawHeaders);
      }

      // Determine new method:
      // 303: always GET
      // 301/302: GET for POST (historical behavior), keep for others
      // 307/308: keep method and body
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

      // Inject cookies for the new URL
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

      // Strip sensitive headers on cross-origin redirects
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
