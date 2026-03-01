/**
 * NLcURL client.
 *
 * The primary public interface for making HTTP requests with browser
 * fingerprint impersonation.  Provides both a session-based API for
 * persistent connections and cookie handling, and standalone convenience
 * functions for one-off requests.
 */

import type {
  NLcURLRequest,
  NLcURLSessionConfig,
  RequestBody,
} from './request.js';
import { NLcURLResponse } from './response.js';
import { NLcURLSession, type RequestOptions } from './session.js';

/**
 * Create a new persistent session.
 *
 * Sessions maintain a connection pool, cookie jar, and default
 * configuration across multiple requests.
 *
 * @example
 * ```ts
 * const session = createSession({ impersonate: 'chrome136' });
 * const response = await session.get('https://httpbin.org/get');
 * console.log(response.json());
 * session.close();
 * ```
 */
export function createSession(config?: NLcURLSessionConfig): NLcURLSession {
  return new NLcURLSession(config);
}

// ---- One-shot request functions ----

/**
 * Send an HTTP request.
 *
 * Creates a temporary session, sends the request, and closes the session.
 * For multiple requests, use `createSession()` instead for better
 * performance via connection reuse.
 *
 * @example
 * ```ts
 * const resp = await request({
 *   url: 'https://httpbin.org/get',
 *   impersonate: 'chrome136',
 * });
 * ```
 */
export async function request(input: NLcURLRequest): Promise<NLcURLResponse> {
  const session = new NLcURLSession(extractSessionConfig(input));
  try {
    return await session.request(input);
  } finally {
    session.close();
  }
}

/**
 * Send a GET request.
 */
export async function get(
  url: string,
  options?: RequestOptions & { impersonate?: string },
): Promise<NLcURLResponse> {
  return request({ ...options, url, method: 'GET' });
}

/**
 * Send a POST request.
 */
export async function post(
  url: string,
  body?: RequestBody,
  options?: RequestOptions & { impersonate?: string },
): Promise<NLcURLResponse> {
  return request({ ...options, url, method: 'POST', body });
}

/**
 * Send a PUT request.
 */
export async function put(
  url: string,
  body?: RequestBody,
  options?: RequestOptions & { impersonate?: string },
): Promise<NLcURLResponse> {
  return request({ ...options, url, method: 'PUT', body });
}

/**
 * Send a PATCH request.
 */
export async function patch(
  url: string,
  body?: RequestBody,
  options?: RequestOptions & { impersonate?: string },
): Promise<NLcURLResponse> {
  return request({ ...options, url, method: 'PATCH', body });
}

/**
 * Send a DELETE request.
 */
export async function del(
  url: string,
  options?: RequestOptions & { impersonate?: string },
): Promise<NLcURLResponse> {
  return request({ ...options, url, method: 'DELETE' });
}

/**
 * Send a HEAD request.
 */
export async function head(
  url: string,
  options?: RequestOptions & { impersonate?: string },
): Promise<NLcURLResponse> {
  return request({ ...options, url, method: 'HEAD' });
}

// ---- Internal ----

/**
 * Extract session-level configuration from a request object.
 */
function extractSessionConfig(req: NLcURLRequest): NLcURLSessionConfig {
  return {
    impersonate: req.impersonate,
    ja3: req.ja3,
    akamai: req.akamai,
    stealth: req.stealth,
    proxy: req.proxy,
    proxyAuth: req.proxyAuth,
    insecure: req.insecure,
    httpVersion: req.httpVersion,
    timeout: req.timeout,
    acceptEncoding: req.acceptEncoding,
  };
}
