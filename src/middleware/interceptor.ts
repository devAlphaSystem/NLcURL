
import type { NLcURLRequest } from '../core/request.js';
import { NLcURLResponse } from '../core/response.js';

/**
 * A function that inspects and optionally transforms an outgoing request before
 * it is sent. May be synchronous or asynchronous.
 *
 * @callback RequestInterceptor
 * @param {NLcURLRequest} request - The outgoing request descriptor.
 * @returns {NLcURLRequest | Promise<NLcURLRequest>} The (potentially modified) request.
 */
export type RequestInterceptor = (
  request: NLcURLRequest,
) => NLcURLRequest | Promise<NLcURLRequest>;

/**
 * A function that inspects and optionally transforms an incoming response before
 * it is returned to the caller. May be synchronous or asynchronous.
 *
 * @callback ResponseInterceptor
 * @param {NLcURLResponse} response - The received response.
 * @returns {NLcURLResponse | Promise<NLcURLResponse>} The (potentially modified) response.
 */
export type ResponseInterceptor = (
  response: NLcURLResponse,
) => NLcURLResponse | Promise<NLcURLResponse>;

/**
 * Maintains ordered lists of request and response interceptors and applies
 * them sequentially. Interceptors are invoked in the order they were added.
 */
export class InterceptorChain {
  private readonly requestInterceptors: RequestInterceptor[] = [];
  private readonly responseInterceptors: ResponseInterceptor[] = [];

  /**
   * Registers a request interceptor. Interceptors are applied in registration order.
   *
   * @param {RequestInterceptor} fn - Interceptor function to add.
   * @returns {this} This instance for chaining.
   */
  addRequestInterceptor(fn: RequestInterceptor): this {
    this.requestInterceptors.push(fn);
    return this;
  }

  /**
   * Registers a response interceptor. Interceptors are applied in registration order.
   *
   * @param {ResponseInterceptor} fn - Interceptor function to add.
   * @returns {this} This instance for chaining.
   */
  addResponseInterceptor(fn: ResponseInterceptor): this {
    this.responseInterceptors.push(fn);
    return this;
  }

  /**
   * Passes `request` through all registered request interceptors in order and
   * returns the final transformed request.
   *
   * @param {NLcURLRequest} request - Originating request descriptor.
   * @returns {Promise<NLcURLRequest>} The request after all interceptors have run.
   */
  async processRequest(request: NLcURLRequest): Promise<NLcURLRequest> {
    let req = request;
    for (const fn of this.requestInterceptors) {
      req = await fn(req);
    }
    return req;
  }

  /**
   * Passes `response` through all registered response interceptors in order and
   * returns the final transformed response.
   *
   * @param {NLcURLResponse} response - Received response.
   * @returns {Promise<NLcURLResponse>} The response after all interceptors have run.
   */
  async processResponse(response: NLcURLResponse): Promise<NLcURLResponse> {
    let resp = response;
    for (const fn of this.responseInterceptors) {
      resp = await fn(resp);
    }
    return resp;
  }
}
