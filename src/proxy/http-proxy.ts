/**
 * HTTP CONNECT proxy tunneling.
 *
 * Establishes a TCP tunnel through an HTTP proxy using the CONNECT
 * method, then returns the raw socket for TLS negotiation.
 */

import * as net from 'node:net';
import { ProxyError } from '../core/errors.js';

export interface HttpProxyOptions {
  host: string;
  port: number;
  /** Proxy authentication (user:pass). */
  auth?: string;
  /** Timeout in milliseconds. */
  timeout?: number;
}

/**
 * Connect to a target host:port through an HTTP CONNECT proxy.
 *
 * Returns a raw TCP socket with the tunnel established, ready for
 * TLS handshake.
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
      // Send CONNECT request
      let connectReq = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\n`;
      connectReq += `Host: ${targetHost}:${targetPort}\r\n`;

      if (proxy.auth) {
        const encoded = Buffer.from(proxy.auth).toString('base64');
        connectReq += `Proxy-Authorization: Basic ${encoded}\r\n`;
      }

      connectReq += '\r\n';
      socket.write(connectReq);

      // Read proxy response
      let buffer = '';

      const onData = (chunk: Buffer) => {
        buffer += chunk.toString('latin1');
        const headerEnd = buffer.indexOf('\r\n\r\n');
        if (headerEnd >= 0) {
          socket.removeListener('data', onData);

          // Parse status line
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

          // Push any remaining data back
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
