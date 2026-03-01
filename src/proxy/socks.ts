/**
 * SOCKS proxy support (SOCKS4, SOCKS4a, SOCKS5).
 *
 * Implements the SOCKS protocol for tunneling TCP connections through
 * SOCKS proxies.  Zero dependencies.
 */

import * as net from 'node:net';
import { ProxyError } from '../core/errors.js';

export interface SocksProxyOptions {
  host: string;
  port: number;
  /** SOCKS version: 4, 4 (with 4a extension), or 5. */
  version: 4 | 5;
  /** Username for SOCKS5 authentication. */
  username?: string;
  /** Password for SOCKS5 authentication. */
  password?: string;
  /** Timeout in milliseconds. */
  timeout?: number;
}

/**
 * Connect to a target through a SOCKS proxy.
 */
export async function socksConnect(
  proxy: SocksProxyOptions,
  targetHost: string,
  targetPort: number,
): Promise<net.Socket> {
  const socket = await tcpConnect(proxy.host, proxy.port, proxy.timeout);

  try {
    if (proxy.version === 5) {
      await socks5Handshake(socket, proxy, targetHost, targetPort);
    } else {
      await socks4Connect(socket, targetHost, targetPort);
    }
    return socket;
  } catch (err) {
    socket.destroy();
    throw err;
  }
}

// ---- SOCKS5 ----

async function socks5Handshake(
  socket: net.Socket,
  proxy: SocksProxyOptions,
  host: string,
  port: number,
): Promise<void> {
  // 1. Authentication negotiation
  const hasAuth = proxy.username && proxy.password;
  const methods = hasAuth ? Buffer.from([0x05, 0x02, 0x00, 0x02]) : Buffer.from([0x05, 0x01, 0x00]);
  await socketWrite(socket, methods);

  const authResponse = await socketRead(socket, 2);
  if (authResponse[0] !== 0x05) {
    throw new ProxyError('Invalid SOCKS5 response');
  }

  const selectedMethod = authResponse[1]!;

  if (selectedMethod === 0x02 && hasAuth) {
    // Username/password authentication (RFC 1929)
    const user = Buffer.from(proxy.username!, 'utf-8');
    const pass = Buffer.from(proxy.password!, 'utf-8');
    const authReq = Buffer.alloc(3 + user.length + pass.length);
    authReq[0] = 0x01; // version
    authReq[1] = user.length;
    user.copy(authReq, 2);
    authReq[2 + user.length] = pass.length;
    pass.copy(authReq, 3 + user.length);
    await socketWrite(socket, authReq);

    const authResult = await socketRead(socket, 2);
    if (authResult[1] !== 0x00) {
      throw new ProxyError('SOCKS5 authentication failed');
    }
  } else if (selectedMethod === 0xff) {
    throw new ProxyError('SOCKS5 proxy rejected all authentication methods');
  }

  // 2. Connection request
  const hostBuf = Buffer.from(host, 'utf-8');
  const req = Buffer.alloc(4 + 1 + hostBuf.length + 2);
  req[0] = 0x05; // version
  req[1] = 0x01; // CONNECT
  req[2] = 0x00; // reserved
  req[3] = 0x03; // DOMAINNAME
  req[4] = hostBuf.length;
  hostBuf.copy(req, 5);
  req.writeUInt16BE(port, 5 + hostBuf.length);
  await socketWrite(socket, req);

  // 3. Read response
  const resp = await socketRead(socket, 4);
  if (resp[0] !== 0x05) {
    throw new ProxyError('Invalid SOCKS5 response');
  }
  if (resp[1] !== 0x00) {
    const codes: Record<number, string> = {
      0x01: 'general SOCKS server failure',
      0x02: 'connection not allowed by ruleset',
      0x03: 'network unreachable',
      0x04: 'host unreachable',
      0x05: 'connection refused',
      0x06: 'TTL expired',
      0x07: 'command not supported',
      0x08: 'address type not supported',
    };
    throw new ProxyError(`SOCKS5 connect failed: ${codes[resp[1]!] ?? 'unknown error'}`);
  }

  // Read bound address (we don't use it, but must consume the bytes)
  const addrType = resp[3]!;
  if (addrType === 0x01) {
    // IPv4
    await socketRead(socket, 4 + 2);
  } else if (addrType === 0x03) {
    // Domain
    const lenBuf = await socketRead(socket, 1);
    await socketRead(socket, lenBuf[0]! + 2);
  } else if (addrType === 0x04) {
    // IPv6
    await socketRead(socket, 16 + 2);
  }
}

// ---- SOCKS4/4a ----

async function socks4Connect(
  socket: net.Socket,
  host: string,
  port: number,
): Promise<void> {
  // SOCKS4a: use 0.0.0.1 as IP and append hostname
  const hostBuf = Buffer.from(host + '\0', 'utf-8');
  const req = Buffer.alloc(9 + hostBuf.length);
  req[0] = 0x04; // version
  req[1] = 0x01; // CONNECT
  req.writeUInt16BE(port, 2);
  // IP = 0.0.0.1 (triggers SOCKS4a)
  req[4] = 0;
  req[5] = 0;
  req[6] = 0;
  req[7] = 1;
  req[8] = 0; // user ID null terminator
  hostBuf.copy(req, 9);

  await socketWrite(socket, req);

  const resp = await socketRead(socket, 8);
  if (resp[1] !== 0x5a) {
    throw new ProxyError(`SOCKS4 connect failed: status 0x${resp[1]!.toString(16)}`);
  }
}

// ---- Helpers ----

function tcpConnect(host: string, port: number, timeout?: number): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const socket = net.createConnection({ host, port });

    const timeoutMs = timeout ?? 30_000;
    let timer: ReturnType<typeof setTimeout> | undefined;

    if (timeoutMs > 0) {
      timer = setTimeout(() => {
        if (!settled) {
          settled = true;
          socket.destroy();
          reject(new ProxyError('SOCKS proxy connection timed out'));
        }
      }, timeoutMs);
    }

    socket.once('connect', () => {
      if (!settled) {
        settled = true;
        if (timer) clearTimeout(timer);
        resolve(socket);
      }
    });

    socket.once('error', (err) => {
      if (!settled) {
        settled = true;
        if (timer) clearTimeout(timer);
        reject(new ProxyError(`SOCKS proxy: ${err.message}`));
      }
    });
  });
}

function socketWrite(socket: net.Socket, data: Buffer): Promise<void> {
  return new Promise((resolve, reject) => {
    socket.write(data, (err) => {
      if (err) reject(new ProxyError(err.message));
      else resolve();
    });
  });
}

function socketRead(socket: net.Socket, length: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    let settled = false;

    const onData = (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length >= length) {
        settled = true;
        socket.removeListener('data', onData);
        socket.removeListener('error', onError);
        const result = buffer.subarray(0, length);
        if (buffer.length > length) {
          socket.unshift(buffer.subarray(length));
        }
        resolve(result);
      }
    };

    const onError = (err: Error) => {
      if (!settled) {
        settled = true;
        socket.removeListener('data', onData);
        reject(new ProxyError(err.message));
      }
    };

    socket.on('data', onData);
    socket.once('error', onError);
  });
}
