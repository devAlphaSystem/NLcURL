
import * as net from 'node:net';
import { ProxyError } from '../core/errors.js';

/**
 * Options for establishing a connection through an HTTP CONNECT proxy.
 *
 * @typedef  {Object}   HttpProxyOptions
 * @property {string}   host      - Proxy server hostname or IP address.
 * @property {number}   port      - Proxy server port.
 * @property {string}   [auth]    - Proxy credentials in `username:password` format (used for Basic auth).
 * @property {number}   [timeout] - Connection timeout in milliseconds (default: 30 000).
 * @property {4 | 6}   [family]  - IP address family to use when resolving the proxy host.
 */
export interface HttpProxyOptions {
  host: string;
  port: number;
  auth?: string;
  timeout?: number;
  family?: 4 | 6;
}

/**
 * Opens a TCP connection to an HTTP CONNECT proxy and tunnels through it to
 * `targetHost:targetPort`. Resolves with the raw socket once the tunnel is
 * established.
 *
 * @param {HttpProxyOptions} proxy      - Proxy server connection details.
 * @param {string}           targetHost - Destination hostname or IP to tunnel to.
 * @param {number}           targetPort - Destination port to tunnel to.
 * @returns {Promise<net.Socket>} Plain TCP socket connected through the proxy tunnel.
 * @throws {ProxyError} If the connection times out or the proxy rejects the CONNECT request.
 */
export async function httpProxyConnect(
  proxy: HttpProxyOptions,
  targetHost: string,
  targetPort: number,
): Promise<net.Socket> {
  return new Promise<net.Socket>((resolve, reject) => {
    let settled = false;
    const socket = net.createConnection({
      host: proxy.host,
      port: proxy.port,
      family: proxy.family,
    });

    const timeoutMs = proxy.timeout ?? 30_000;
    let timer: ReturnType<typeof setTimeout> | undefined;

    if (timeoutMs > 0) {
      timer = setTimeout(() => {
        if (!settled) {
          settled = true;
          socket.destroy();
          reject(new ProxyError('Proxy connection timed out'));
        }
      }, timeoutMs);
    }

    socket.once('connect', () => {
      let connectReq = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\n`;
      connectReq += `Host: ${targetHost}:${targetPort}\r\n`;

      if (proxy.auth) {
        const encoded = Buffer.from(proxy.auth).toString('base64');
        connectReq += `Proxy-Authorization: Basic ${encoded}\r\n`;
      }

      connectReq += '\r\n';
      socket.write(connectReq);

      let buffer = '';

      const onData = (chunk: Buffer) => {
        buffer += chunk.toString('latin1');
        const headerEnd = buffer.indexOf('\r\n\r\n');
        if (headerEnd >= 0) {
          socket.removeListener('data', onData);

          const statusLine = buffer.substring(0, buffer.indexOf('\r\n'));
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
            socket.unshift(Buffer.from(remaining, 'latin1'));
          }

          resolve(socket);
        }
      };

      socket.on('data', onData);
    });

    socket.once('error', (err) => {
      if (!settled) {
        settled = true;
        if (timer) clearTimeout(timer);
        reject(new ProxyError(`Proxy connection failed: ${err.message}`));
      }
    });
  });
}
