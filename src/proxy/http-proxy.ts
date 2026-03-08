import * as net from "node:net";
import * as tls from "node:tls";
import { ProxyError } from "../core/errors.js";

/** Configuration for connecting through an HTTP CONNECT proxy. */
export interface HttpProxyOptions {
  /** Proxy server hostname or IP address. */
  host: string;
  /** Proxy server port. */
  port: number;
  /** Optional `Proxy-Authorization` header value. */
  auth?: string;
  /** Connection timeout in milliseconds. */
  timeout?: number;
  /** IP address family to use (`4` or `6`). */
  family?: 4 | 6;
  /** Connect to the proxy over TLS (HTTPS proxy). */
  secure?: boolean;
}

/**
 * Establish a TCP tunnel through an HTTP CONNECT proxy.
 *
 * @param {HttpProxyOptions} proxy - Proxy connection options.
 * @param {string} targetHost - Destination hostname.
 * @param {number} targetPort - Destination port.
 * @returns {Promise<net.Socket>} Connected socket tunneled through the proxy.
 */
export async function httpProxyConnect(proxy: HttpProxyOptions, targetHost: string, targetPort: number): Promise<net.Socket> {
  return new Promise<net.Socket>((resolve, reject) => {
    let settled = false;

    let socket: net.Socket | tls.TLSSocket;
    if (proxy.secure) {
      const tlsOpts = {
        host: proxy.host,
        port: proxy.port,
        rejectUnauthorized: true,
        ...(proxy.family ? { family: proxy.family } : {}),
      };
      socket = tls.connect(tlsOpts);
    } else {
      socket = net.createConnection({
        host: proxy.host,
        port: proxy.port,
        family: proxy.family,
      });
    }

    const timeoutMs = proxy.timeout ?? 30_000;
    let timer: ReturnType<typeof setTimeout> | undefined;

    if (timeoutMs > 0) {
      timer = setTimeout(() => {
        if (!settled) {
          settled = true;
          socket.destroy();
          reject(new ProxyError("Proxy connection timed out"));
        }
      }, timeoutMs);
    }

    socket.once(proxy.secure ? "secureConnect" : "connect", () => {
      let connectReq = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\n`;
      connectReq += `Host: ${targetHost}:${targetPort}\r\n`;

      if (proxy.auth) {
        const encoded = Buffer.from(proxy.auth).toString("base64");
        connectReq += `Proxy-Authorization: Basic ${encoded}\r\n`;
      }

      connectReq += "\r\n";
      socket.write(connectReq);

      let buffer = "";
      const MAX_CONNECT_RESPONSE_SIZE = 16384;

      const onData = (chunk: Buffer) => {
        buffer += chunk.toString("latin1");
        if (buffer.length > MAX_CONNECT_RESPONSE_SIZE) {
          settled = true;
          if (timer) clearTimeout(timer);
          socket.removeListener("data", onData);
          socket.destroy();
          reject(new ProxyError("Proxy CONNECT response headers exceed size limit"));
          return;
        }
        const headerEnd = buffer.indexOf("\r\n\r\n");
        if (headerEnd >= 0) {
          socket.removeListener("data", onData);

          const statusLine = buffer.substring(0, buffer.indexOf("\r\n"));
          const match = /^HTTP\/\d\.\d\s+(\d{3})/.exec(statusLine);

          if (!match) {
            settled = true;
            if (timer) clearTimeout(timer);
            socket.destroy();
            reject(new ProxyError(`Invalid proxy response: ${statusLine.substring(0, 100)}`));
            return;
          }

          const statusCode = parseInt(match[1]!, 10);
          if (statusCode !== 200) {
            settled = true;
            if (timer) clearTimeout(timer);
            socket.destroy();
            reject(new ProxyError(`Proxy CONNECT failed with status ${statusCode}`));
            return;
          }

          settled = true;
          if (timer) clearTimeout(timer);

          const remaining = buffer.substring(headerEnd + 4);
          if (remaining.length > 0) {
            socket.unshift(Buffer.from(remaining, "latin1"));
          }

          resolve(socket);
        }
      };

      socket.on("data", onData);
    });

    socket.once("error", (err) => {
      if (!settled) {
        settled = true;
        if (timer) clearTimeout(timer);
        reject(new ProxyError(`Proxy connection failed: ${err.message}`));
      }
    });
  });
}
