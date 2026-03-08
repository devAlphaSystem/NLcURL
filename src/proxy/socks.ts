import * as net from "node:net";
import { ProxyError } from "../core/errors.js";

/** Configuration for connecting through a SOCKS proxy. */
export interface SocksProxyOptions {
  /** Proxy server hostname or IP address. */
  host: string;
  /** Proxy server port. */
  port: number;
  /** SOCKS protocol version (`4` or `5`). */
  version: 4 | 5;
  /** Username for SOCKS5 authentication. */
  username?: string;
  /** Password for SOCKS5 authentication. */
  password?: string;
  /** Connection timeout in milliseconds. */
  timeout?: number;
  /** IP address family to use (`4` or `6`). */
  family?: 4 | 6;
}

/**
 * Establish a TCP connection through a SOCKS4 or SOCKS5 proxy.
 *
 * @param {SocksProxyOptions} proxy - SOCKS proxy options including version and optional credentials.
 * @param {string} targetHost - Destination hostname.
 * @param {number} targetPort - Destination port.
 * @returns {Promise<net.Socket>} Connected socket tunneled through the SOCKS proxy.
 */
export async function socksConnect(proxy: SocksProxyOptions, targetHost: string, targetPort: number): Promise<net.Socket> {
  const socket = await tcpConnect(proxy.host, proxy.port, proxy.timeout, proxy.family);

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

async function socks5Handshake(socket: net.Socket, proxy: SocksProxyOptions, host: string, port: number): Promise<void> {
  const hasAuth = proxy.username && proxy.password;
  const methods = hasAuth ? Buffer.from([0x05, 0x02, 0x00, 0x02]) : Buffer.from([0x05, 0x01, 0x00]);
  await socketWrite(socket, methods);

  const authResponse = await socketRead(socket, 2);
  if (authResponse[0] !== 0x05) {
    throw new ProxyError("Invalid SOCKS5 response");
  }

  const selectedMethod = authResponse[1]!;

  if (selectedMethod === 0x02 && hasAuth) {
    const user = Buffer.from(proxy.username!, "utf-8");
    const pass = Buffer.from(proxy.password!, "utf-8");
    if (user.length > 255) {
      throw new ProxyError("SOCKS5 username exceeds 255 bytes");
    }
    if (pass.length > 255) {
      throw new ProxyError("SOCKS5 password exceeds 255 bytes");
    }
    const authReq = Buffer.alloc(3 + user.length + pass.length);
    authReq[0] = 0x01;
    authReq[1] = user.length;
    user.copy(authReq, 2);
    authReq[2 + user.length] = pass.length;
    pass.copy(authReq, 3 + user.length);
    await socketWrite(socket, authReq);

    const authResult = await socketRead(socket, 2);
    if (authResult.length < 2 || authResult[1] !== 0x00) {
      throw new ProxyError("SOCKS5 authentication failed");
    }
  } else if (selectedMethod === 0xff) {
    throw new ProxyError("SOCKS5 proxy rejected all authentication methods");
  }

  const hostBuf = Buffer.from(host, "utf-8");
  if (hostBuf.length > 255) {
    throw new ProxyError(`SOCKS5 hostname exceeds 255 bytes: ${host.substring(0, 40)}`);
  }
  const req = Buffer.alloc(4 + 1 + hostBuf.length + 2);
  req[0] = 0x05;
  req[1] = 0x01;
  req[2] = 0x00;
  req[3] = 0x03;
  req[4] = hostBuf.length;
  hostBuf.copy(req, 5);
  req.writeUInt16BE(port, 5 + hostBuf.length);
  await socketWrite(socket, req);

  const resp = await socketRead(socket, 4);
  if (resp[0] !== 0x05) {
    throw new ProxyError("Invalid SOCKS5 response");
  }
  if (resp[1] !== 0x00) {
    const codes: Record<number, string> = {
      0x01: "general SOCKS server failure",
      0x02: "connection not allowed by ruleset",
      0x03: "network unreachable",
      0x04: "host unreachable",
      0x05: "connection refused",
      0x06: "TTL expired",
      0x07: "command not supported",
      0x08: "address type not supported",
    };
    throw new ProxyError(`SOCKS5 connect failed: ${codes[resp[1]!] ?? "unknown error"}`);
  }

  const addrType = resp[3]!;
  if (addrType === 0x01) {
    await socketRead(socket, 4 + 2);
  } else if (addrType === 0x03) {
    const lenBuf = await socketRead(socket, 1);
    await socketRead(socket, lenBuf[0]! + 2);
  } else if (addrType === 0x04) {
    await socketRead(socket, 16 + 2);
  }
}

async function socks4Connect(socket: net.Socket, host: string, port: number): Promise<void> {
  const hostBuf = Buffer.from(host + "\0", "utf-8");
  const req = Buffer.alloc(9 + hostBuf.length);
  req[0] = 0x04;
  req[1] = 0x01;
  req.writeUInt16BE(port, 2);
  req[4] = 0;
  req[5] = 0;
  req[6] = 0;
  req[7] = 1;
  req[8] = 0;
  hostBuf.copy(req, 9);

  await socketWrite(socket, req);

  const resp = await socketRead(socket, 8);
  if (resp[1] !== 0x5a) {
    throw new ProxyError(`SOCKS4 connect failed: status 0x${resp[1]!.toString(16)}`);
  }
}

function tcpConnect(host: string, port: number, timeout?: number, family?: 4 | 6): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const socket = net.createConnection({ host, port, family });

    const timeoutMs = timeout ?? 30_000;
    let timer: ReturnType<typeof setTimeout> | undefined;

    if (timeoutMs > 0) {
      timer = setTimeout(() => {
        if (!settled) {
          settled = true;
          socket.destroy();
          reject(new ProxyError("SOCKS proxy connection timed out"));
        }
      }, timeoutMs);
    }

    socket.once("connect", () => {
      if (!settled) {
        settled = true;
        if (timer) clearTimeout(timer);
        resolve(socket);
      }
    });

    socket.once("error", (err) => {
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

const MAX_SOCKS_READ = 4096;

function socketRead(socket: net.Socket, length: number, timeout?: number): Promise<Buffer> {
  if (length > MAX_SOCKS_READ) {
    throw new ProxyError(`SOCKS read request ${length} exceeds ${MAX_SOCKS_READ} byte limit`);
  }
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    let settled = false;

    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeoutMs = timeout ?? 30_000;
    if (timeoutMs > 0) {
      timer = setTimeout(() => {
        if (!settled) {
          settled = true;
          cleanup();
          reject(new ProxyError("SOCKS read timed out"));
        }
      }, timeoutMs);
    }

    const cleanup = () => {
      if (timer) clearTimeout(timer);
      socket.removeListener("data", onData);
      socket.removeListener("error", onError);
      socket.removeListener("close", onClose);
    };

    const onData = (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length >= length) {
        settled = true;
        cleanup();
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
        cleanup();
        reject(new ProxyError(err.message));
      }
    };

    const onClose = () => {
      if (!settled) {
        settled = true;
        cleanup();
        reject(new ProxyError("SOCKS socket closed before read completed"));
      }
    };

    socket.on("data", onData);
    socket.once("error", onError);
    socket.once("close", onClose);
  });
}
