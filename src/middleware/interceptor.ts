import type { NLcURLRequest } from "../core/request.js";
import { NLcURLResponse } from "../core/response.js";

/** Function that transforms a request before it is sent. */
export type RequestInterceptor = (request: NLcURLRequest) => NLcURLRequest | Promise<NLcURLRequest>;

/** Function that transforms a response after it is received. */
export type ResponseInterceptor = (response: NLcURLResponse) => NLcURLResponse | Promise<NLcURLResponse>;

/** Ordered chain of request and response interceptors. */
export class InterceptorChain {
  private readonly requestInterceptors: RequestInterceptor[] = [];
  private readonly responseInterceptors: ResponseInterceptor[] = [];

  /**
   * Register a request interceptor.
   *
   * @param {RequestInterceptor} fn - Interceptor function.
   * @returns {this} This instance for chaining.
   */
  addRequestInterceptor(fn: RequestInterceptor): this {
    this.requestInterceptors.push(fn);
    return this;
  }

  /**
   * Register a response interceptor.
   *
   * @param {ResponseInterceptor} fn - Interceptor function.
   * @returns {this} This instance for chaining.
   */
  addResponseInterceptor(fn: ResponseInterceptor): this {
    this.responseInterceptors.push(fn);
    return this;
  }

  /**
   * Run all request interceptors in order.
   *
   * @param {NLcURLRequest} request - Original request.
   * @returns {Promise<NLcURLRequest>} Transformed request.
   */
  async processRequest(request: NLcURLRequest): Promise<NLcURLRequest> {
    let req = request;
    for (const fn of this.requestInterceptors) {
      req = await fn(req);
    }
    return req;
  }

  /**
   * Run all response interceptors in order.
   *
   * @param {NLcURLResponse} response - Original response.
   * @returns {Promise<NLcURLResponse>} Transformed response.
   */
  async processResponse(response: NLcURLResponse): Promise<NLcURLResponse> {
    let resp = response;
    for (const fn of this.responseInterceptors) {
      resp = await fn(resp);
    }
    return resp;
  }
}
