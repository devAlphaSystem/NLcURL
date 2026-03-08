import type { NLcURLRequest, NLcURLSessionConfig, RequestBody } from "./request.js";
import { NLcURLResponse } from "./response.js";
import { NLcURLSession, type RequestOptions } from "./session.js";

/**
 * Creates a new session with optional configuration for connection reuse,
 * cookie persistence, caching, and other session-level features.
 *
 * @param {NLcURLSessionConfig} [config] - Session configuration options.
 * @returns {NLcURLSession} A new session instance.
 */
export function createSession(config?: NLcURLSessionConfig): NLcURLSession {
  return new NLcURLSession(config);
}

/**
 * Sends a one-shot HTTP request using a temporary session. Supports streaming
 * responses when `input.stream` is `true`.
 *
 * @param {NLcURLRequest} input - The full request descriptor including URL, method, headers, and body.
 * @returns {Promise<NLcURLResponse>} Resolves with the server response.
 */
export async function request(input: NLcURLRequest): Promise<NLcURLResponse> {
  const session = new NLcURLSession(extractSessionConfig(input));
  if (input.stream) {
    let response: NLcURLResponse;
    try {
      response = await session.request(input);
    } catch (err) {
      session.close();
      throw err;
    }
    const cleanup = () => {
      session.close();
    };
    response.body?.once("close", cleanup);
    if (response.body === null) session.close();
    return response;
  }
  try {
    return await session.request(input);
  } finally {
    session.close();
  }
}

/**
 * Sends an HTTP GET request.
 *
 * @param {string} url - The target URL.
 * @param {RequestOptions & { impersonate?: string }} [options] - Optional request configuration.
 * @returns {Promise<NLcURLResponse>} Resolves with the server response.
 */
export async function get(url: string, options?: RequestOptions & { impersonate?: string }): Promise<NLcURLResponse> {
  return request({ ...options, url, method: "GET" });
}

/**
 * Sends an HTTP POST request.
 *
 * @param {string} url - The target URL.
 * @param {RequestBody} [body] - The request body.
 * @param {RequestOptions & { impersonate?: string }} [options] - Optional request configuration.
 * @returns {Promise<NLcURLResponse>} Resolves with the server response.
 */
export async function post(url: string, body?: RequestBody, options?: RequestOptions & { impersonate?: string }): Promise<NLcURLResponse> {
  return request({ ...options, url, method: "POST", body });
}

/**
 * Sends an HTTP PUT request.
 *
 * @param {string} url - The target URL.
 * @param {RequestBody} [body] - The request body.
 * @param {RequestOptions & { impersonate?: string }} [options] - Optional request configuration.
 * @returns {Promise<NLcURLResponse>} Resolves with the server response.
 */
export async function put(url: string, body?: RequestBody, options?: RequestOptions & { impersonate?: string }): Promise<NLcURLResponse> {
  return request({ ...options, url, method: "PUT", body });
}

/**
 * Sends an HTTP PATCH request.
 *
 * @param {string} url - The target URL.
 * @param {RequestBody} [body] - The request body.
 * @param {RequestOptions & { impersonate?: string }} [options] - Optional request configuration.
 * @returns {Promise<NLcURLResponse>} Resolves with the server response.
 */
export async function patch(url: string, body?: RequestBody, options?: RequestOptions & { impersonate?: string }): Promise<NLcURLResponse> {
  return request({ ...options, url, method: "PATCH", body });
}

/**
 * Sends an HTTP DELETE request.
 *
 * @param {string} url - The target URL.
 * @param {RequestOptions & { impersonate?: string }} [options] - Optional request configuration.
 * @returns {Promise<NLcURLResponse>} Resolves with the server response.
 */
export async function del(url: string, options?: RequestOptions & { impersonate?: string }): Promise<NLcURLResponse> {
  return request({ ...options, url, method: "DELETE" });
}

/**
 * Sends an HTTP HEAD request.
 *
 * @param {string} url - The target URL.
 * @param {RequestOptions & { impersonate?: string }} [options] - Optional request configuration.
 * @returns {Promise<NLcURLResponse>} Resolves with the server response.
 */
export async function head(url: string, options?: RequestOptions & { impersonate?: string }): Promise<NLcURLResponse> {
  return request({ ...options, url, method: "HEAD" });
}

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
    cookieJar: req.cookieJar,
    logger: req.logger,
    tls: req.tls,
    throwOnError: req.throwOnError,
    cacheConfig: req.cache ? { mode: req.cache } : undefined,
    hsts: undefined,
  };
}
