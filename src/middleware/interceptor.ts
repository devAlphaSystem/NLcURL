/**
 * Request/response interceptor middleware.
 */

import type { NLcURLRequest } from '../core/request.js';
import { NLcURLResponse } from '../core/response.js';

/**
 * A function that can modify a request before it is sent.
 */
export type RequestInterceptor = (
  request: NLcURLRequest,
) => NLcURLRequest | Promise<NLcURLRequest>;

/**
 * A function that can modify or inspect a response after it is received.
 */
export type ResponseInterceptor = (
  response: NLcURLResponse,
) => NLcURLResponse | Promise<NLcURLResponse>;

/**
 * Middleware chain.
 *
 * Interceptors are executed in FIFO order.
 */
export class InterceptorChain {
  private readonly requestInterceptors: RequestInterceptor[] = [];
  private readonly responseInterceptors: ResponseInterceptor[] = [];

  addRequestInterceptor(fn: RequestInterceptor): this {
    this.requestInterceptors.push(fn);
    return this;
  }

  addResponseInterceptor(fn: ResponseInterceptor): this {
    this.responseInterceptors.push(fn);
    return this;
  }

  async processRequest(request: NLcURLRequest): Promise<NLcURLRequest> {
    let req = request;
    for (const fn of this.requestInterceptors) {
      req = await fn(req);
    }
    return req;
  }

  async processResponse(response: NLcURLResponse): Promise<NLcURLResponse> {
    let resp = response;
    for (const fn of this.responseInterceptors) {
      resp = await fn(resp);
    }
    return resp;
  }
}
