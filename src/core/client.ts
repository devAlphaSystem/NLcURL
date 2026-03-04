import type { NLcURLRequest, NLcURLSessionConfig, RequestBody } from "./request.js";
import { NLcURLResponse } from "./response.js";
import { NLcURLSession, type RequestOptions } from "./session.js";

/**
 * Creates a new {@link NLcURLSession} with the given configuration. Use a
 * session when you need to share cookies, connection pools, or interceptors
 * across multiple requests. Call {@link NLcURLSession.close} when finished.
 *
 * @param {NLcURLSessionConfig} [config] - Session-level defaults.
 * @returns {NLcURLSession} A new session instance.
 *
 * @example
 * const session = createSession({ impersonate: 'chrome136' });
 * const r = await session.get('https://example.com');
 * session.close();
 */
export function createSession(config?: NLcURLSessionConfig): NLcURLSession {
  return new NLcURLSession(config);
}

/**
 * Sends a one-shot HTTP request by creating a temporary session internally.
 * The session is closed automatically after the response is received.
 * For repeated requests to the same origin, prefer {@link createSession}.
 *
 * @param {NLcURLRequest} input - Complete request descriptor.
 * @returns {Promise<NLcURLResponse>} Resolves with the server response.
 * @throws {AbortError}      If the `signal` in `input` fires before completion.
 * @throws {TimeoutError}    If any configured timeout is exceeded.
 * @throws {ConnectionError} If the TCP connection cannot be established.
 * @throws {TLSError}        If the TLS handshake fails.
 * @throws {ProxyError}      If the proxy tunnel cannot be established.
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
    const cleanup = () => session.close();
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
 * Issues a one-shot `GET` request.
 *
 * @param {string}                                              url      - Absolute URL to request.
 * @param {RequestOptions & { impersonate?: string }}          [options] - Optional per-request settings.
 * @returns {Promise<NLcURLResponse>} Resolves with the server response.
 */
export async function get(url: string, options?: RequestOptions & { impersonate?: string }): Promise<NLcURLResponse> {
  return request({ ...options, url, method: "GET" });
}

/**
 * Issues a one-shot `POST` request.
 *
 * @param {string}                                              url      - Absolute URL to request.
 * @param {RequestBody}                                         [body]   - Request body payload.
 * @param {RequestOptions & { impersonate?: string }}          [options] - Optional per-request settings.
 * @returns {Promise<NLcURLResponse>} Resolves with the server response.
 */
export async function post(url: string, body?: RequestBody, options?: RequestOptions & { impersonate?: string }): Promise<NLcURLResponse> {
  return request({ ...options, url, method: "POST", body });
}

/**
 * Issues a one-shot `PUT` request.
 *
 * @param {string}                                              url      - Absolute URL to request.
 * @param {RequestBody}                                         [body]   - Request body payload.
 * @param {RequestOptions & { impersonate?: string }}          [options] - Optional per-request settings.
 * @returns {Promise<NLcURLResponse>} Resolves with the server response.
 */
export async function put(url: string, body?: RequestBody, options?: RequestOptions & { impersonate?: string }): Promise<NLcURLResponse> {
  return request({ ...options, url, method: "PUT", body });
}

/**
 * Issues a one-shot `PATCH` request.
 *
 * @param {string}                                              url      - Absolute URL to request.
 * @param {RequestBody}                                         [body]   - Request body payload.
 * @param {RequestOptions & { impersonate?: string }}          [options] - Optional per-request settings.
 * @returns {Promise<NLcURLResponse>} Resolves with the server response.
 */
export async function patch(url: string, body?: RequestBody, options?: RequestOptions & { impersonate?: string }): Promise<NLcURLResponse> {
  return request({ ...options, url, method: "PATCH", body });
}

/**
 * Issues a one-shot `DELETE` request.
 *
 * @param {string}                                              url      - Absolute URL to request.
 * @param {RequestOptions & { impersonate?: string }}          [options] - Optional per-request settings.
 * @returns {Promise<NLcURLResponse>} Resolves with the server response.
 */
export async function del(url: string, options?: RequestOptions & { impersonate?: string }): Promise<NLcURLResponse> {
  return request({ ...options, url, method: "DELETE" });
}

/**
 * Issues a one-shot `HEAD` request. The response body will be empty.
 *
 * @param {string}                                              url      - Absolute URL to request.
 * @param {RequestOptions & { impersonate?: string }}          [options] - Optional per-request settings.
 * @returns {Promise<NLcURLResponse>} Resolves with the response (headers only, no body).
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
  };
}
