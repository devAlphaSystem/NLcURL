import * as net from "node:net";
import { lookup } from "node:dns/promises";
import type { DoHResolver } from "../dns/doh-resolver.js";
import { parseARecord, parseAAAARecord } from "../dns/codec.js";
import { RTYPE } from "../dns/types.js";

interface ResolvedAddress {
  address: string;
  family: number;
}

const ATTEMPT_DELAY_MS = 250;

/** Options for the Happy Eyeballs (RFC 8305) connection algorithm. */
export interface HappyEyeballsOptions {
  /** Destination hostname or IP address. */
  host: string;
  /** Destination port. */
  port: number;
  /** Restrict connections to IPv4 (`4`) or IPv6 (`6`). */
  family?: 4 | 6;
  /** Overall connection timeout in milliseconds. */
  timeout?: number;
  /** Abort signal to cancel the connection attempt. */
  signal?: AbortSignal;
  /** DNS-over-HTTPS resolver to use instead of system DNS. */
  dohResolver?: DoHResolver;
}

/** Outcome of a Happy Eyeballs connection attempt. */
export interface HappyEyeballsResult {
  /** Connected TCP socket. */
  socket: net.Socket;
  /** Resolved IP address that was connected to. */
  address: string;
  /** IP address family of the connected socket. */
  family: number;
  /** Time spent on DNS resolution in milliseconds. */
  dnsTimeMs: number;
}

/**
 * Connect to a host using the Happy Eyeballs algorithm (RFC 8305).
 *
 * Races IPv6 and IPv4 connection attempts with a staggered delay
 * for fast fallback.
 *
 * @param {HappyEyeballsOptions} options - Connection options.
 * @returns {Promise<HappyEyeballsResult>} Connected socket and connection metadata.
 */
export async function happyEyeballsConnect(options: HappyEyeballsOptions): Promise<HappyEyeballsResult> {
  const { host, port, family, timeout, signal, dohResolver } = options;

  const ipVersion = net.isIP(host);
  if (ipVersion) {
    const socket = await raceTcpConnections([{ address: host, family: ipVersion }], port, timeout, signal);
    return { socket: socket.socket, address: host, family: ipVersion, dnsTimeMs: 0 };
  }

  const dnsStart = Date.now();
  let addresses: ResolvedAddress[];

  if (dohResolver) {
    addresses = await resolveWithDoH(dohResolver, host, family, signal);
  } else {
    addresses = await lookup(host, { all: true, family: family ?? 0 });
  }
  const dnsTimeMs = Date.now() - dnsStart;

  if (!addresses.length) {
    const err = new Error(`getaddrinfo ENOTFOUND ${host}`) as NodeJS.ErrnoException;
    err.code = "ENOTFOUND";
    throw err;
  }

  const sorted = family ? addresses : interleaveAddressFamilies(addresses);

  const result = await raceTcpConnections(sorted, port, timeout, signal);
  return { socket: result.socket, address: result.address, family: result.family, dnsTimeMs };
}

function interleaveAddressFamilies(addresses: ResolvedAddress[]): ResolvedAddress[] {
  const ipv6: ResolvedAddress[] = [];
  const ipv4: ResolvedAddress[] = [];
  for (const a of addresses) {
    if (a.family === 6) ipv6.push(a);
    else ipv4.push(a);
  }

  const lead = addresses[0]!;
  const primary = lead.family === 4 ? ipv4 : ipv6;
  const secondary = lead.family === 4 ? ipv6 : ipv4;

  const out: ResolvedAddress[] = [];
  const max = Math.max(primary.length, secondary.length);
  for (let i = 0; i < max; i++) {
    const p = primary[i];
    const s = secondary[i];
    if (p) out.push(p);
    if (s) out.push(s);
  }
  return out;
}

interface RaceResult {
  socket: net.Socket;
  address: string;
  family: number;
}

function raceTcpConnections(addresses: ResolvedAddress[], port: number, timeout?: number, signal?: AbortSignal): Promise<RaceResult> {
  if (addresses.length === 1) {
    return singleConnect(addresses[0]!, port, timeout, signal);
  }

  return new Promise<RaceResult>((resolve, reject) => {
    const sockets: net.Socket[] = [];
    const errors: Error[] = [];
    let settled = false;
    let attemptIndex = 0;
    let delayTimer: ReturnType<typeof setTimeout> | undefined;
    let overallTimer: ReturnType<typeof setTimeout> | undefined;
    let abortHandler: (() => void) | undefined;

    const cleanup = (winner?: net.Socket) => {
      if (delayTimer) clearTimeout(delayTimer);
      if (overallTimer) clearTimeout(overallTimer);
      if (signal && abortHandler) signal.removeEventListener("abort", abortHandler);
      for (const s of sockets) {
        if (s !== winner && !s.destroyed) s.destroy();
      }
    };

    const onSettled = (socket: net.Socket, address: string, family: number) => {
      if (settled) {
        socket.destroy();
        return;
      }
      settled = true;
      cleanup(socket);
      resolve({ socket, address, family });
    };

    const onAttemptError = (err: Error) => {
      errors.push(err);
      if (settled) return;

      if (errors.length >= sockets.length && attemptIndex >= addresses.length) {
        settled = true;
        cleanup();
        reject(errors[0] ?? new Error("All connection attempts failed"));
        return;
      }

      if (attemptIndex < addresses.length) {
        if (delayTimer) clearTimeout(delayTimer);
        startNextAttempt();
      }
    };

    const startNextAttempt = () => {
      if (settled || attemptIndex >= addresses.length) return;

      const entry = addresses[attemptIndex++]!;
      const socket = net.createConnection({ host: entry.address, port, family: entry.family as 4 | 6 });
      sockets.push(socket);

      socket.once("connect", () => {
        onSettled(socket, entry.address, entry.family);
      });
      socket.once("error", onAttemptError);

      if (attemptIndex < addresses.length) {
        delayTimer = setTimeout(startNextAttempt, ATTEMPT_DELAY_MS);
      }
    };

    const timeoutMs = timeout ?? 30_000;
    if (timeoutMs > 0) {
      overallTimer = setTimeout(() => {
        if (!settled) {
          settled = true;
          cleanup();
          const err = new Error("TCP connection timed out") as NodeJS.ErrnoException;
          err.code = "ETIMEDOUT";
          reject(err);
        }
      }, timeoutMs);
    }

    if (signal) {
      if (signal.aborted) {
        reject(new Error("Connection aborted"));
        return;
      }
      abortHandler = () => {
        if (!settled) {
          settled = true;
          cleanup();
          reject(new Error("Connection aborted"));
        }
      };
      signal.addEventListener("abort", abortHandler, { once: true });
    }

    startNextAttempt();
  });
}

function singleConnect(entry: ResolvedAddress, port: number, timeout?: number, signal?: AbortSignal): Promise<RaceResult> {
  return new Promise<RaceResult>((resolve, reject) => {
    let settled = false;
    const socket = net.createConnection({ host: entry.address, port, family: entry.family as 4 | 6 });
    let timer: ReturnType<typeof setTimeout> | undefined;
    let abortHandler: (() => void) | undefined;

    const finish = (err?: Error) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      if (signal && abortHandler) signal.removeEventListener("abort", abortHandler);
      if (err) {
        socket.destroy();
        reject(err);
      } else {
        resolve({ socket, address: entry.address, family: entry.family });
      }
    };

    const timeoutMs = timeout ?? 30_000;
    if (timeoutMs > 0) {
      timer = setTimeout(() => {
        const err = new Error("TCP connection timed out") as NodeJS.ErrnoException;
        err.code = "ETIMEDOUT";
        finish(err);
      }, timeoutMs);
    }

    if (signal) {
      if (signal.aborted) {
        socket.destroy();
        reject(new Error("Connection aborted"));
        return;
      }
      abortHandler = () => {
        finish(new Error("Connection aborted"));
      };
      signal.addEventListener("abort", abortHandler, { once: true });
    }

    socket.once("connect", () => {
      finish();
    });
    socket.once("error", (err) => {
      finish(err);
    });
  });
}

async function resolveWithDoH(resolver: DoHResolver, host: string, family: 4 | 6 | undefined, signal?: AbortSignal): Promise<ResolvedAddress[]> {
  const results: ResolvedAddress[] = [];

  try {
    if (!family || family === 6) {
      const aaaa = await resolver.query(host, "AAAA", signal);
      for (const r of aaaa) {
        if (r.type === RTYPE.AAAA && r.data.length === 16) {
          results.push({ address: parseAAAARecord(r.data), family: 6 });
        }
      }
    }

    if (!family || family === 4) {
      const a = await resolver.query(host, "A", signal);
      for (const r of a) {
        if (r.type === RTYPE.A && r.data.length === 4) {
          results.push({ address: parseARecord(r.data), family: 4 });
        }
      }
    }
  } catch {
    return lookup(host, { all: true, family: family ?? 0 });
  }

  if (results.length === 0) {
    return lookup(host, { all: true, family: family ?? 0 });
  }

  return results;
}
