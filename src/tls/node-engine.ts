
import * as tls from 'node:tls';
import * as net from 'node:net';
import { Duplex } from 'node:stream';
import type { ITLSEngine, TLSConnectOptions, TLSConnectionInfo, TLSSocket } from './types.js';
import type { BrowserProfile } from '../fingerprints/types.js';
import { CipherSuite, NamedGroup, SignatureScheme } from './constants.js';
import { TLSError } from '../core/errors.js';

const CIPHER_NAME: ReadonlyMap<number, string> = new Map([
  [CipherSuite.TLS_AES_128_GCM_SHA256, 'TLS_AES_128_GCM_SHA256'],
  [CipherSuite.TLS_AES_256_GCM_SHA384, 'TLS_AES_256_GCM_SHA384'],
  [CipherSuite.TLS_CHACHA20_POLY1305_SHA256, 'TLS_CHACHA20_POLY1305_SHA256'],
  [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 'ECDHE-ECDSA-AES128-GCM-SHA256'],
  [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, 'ECDHE-RSA-AES128-GCM-SHA256'],
  [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, 'ECDHE-ECDSA-AES256-GCM-SHA384'],
  [CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, 'ECDHE-RSA-AES256-GCM-SHA384'],
  [CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, 'ECDHE-ECDSA-CHACHA20-POLY1305'],
  [CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, 'ECDHE-RSA-CHACHA20-POLY1305'],
  [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, 'ECDHE-RSA-AES128-SHA'],
  [CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, 'ECDHE-RSA-AES256-SHA'],
  [CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256, 'AES128-GCM-SHA256'],
  [CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384, 'AES256-GCM-SHA384'],
  [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, 'AES128-SHA'],
  [CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA, 'AES256-SHA'],
  [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, 'ECDHE-ECDSA-AES256-SHA'],
  [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, 'ECDHE-ECDSA-AES128-SHA'],
  [CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA, 'AES256-SHA'],
  [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, 'AES128-SHA'],
]);

const GROUP_NAME: ReadonlyMap<number, string> = new Map([
  [NamedGroup.X25519, 'X25519'],
  [NamedGroup.SECP256R1, 'P-256'],
  [NamedGroup.SECP384R1, 'P-384'],
  [NamedGroup.SECP521R1, 'P-521'],
  [NamedGroup.X448, 'X448'],
  [NamedGroup.FFDHE2048, 'ffdhe2048'],
  [NamedGroup.FFDHE3072, 'ffdhe3072'],
]);

const SIGALG_NAME: ReadonlyMap<number, string> = new Map([
  [SignatureScheme.ECDSA_SECP256R1_SHA256, 'ecdsa_secp256r1_sha256'],
  [SignatureScheme.ECDSA_SECP384R1_SHA384, 'ecdsa_secp384r1_sha384'],
  [SignatureScheme.ECDSA_SECP521R1_SHA512, 'ecdsa_secp521r1_sha512'],
  [SignatureScheme.RSA_PSS_RSAE_SHA256, 'rsa_pss_rsae_sha256'],
  [SignatureScheme.RSA_PSS_RSAE_SHA384, 'rsa_pss_rsae_sha384'],
  [SignatureScheme.RSA_PSS_RSAE_SHA512, 'rsa_pss_rsae_sha512'],
  [SignatureScheme.RSA_PKCS1_SHA256, 'rsa_pkcs1_sha256'],
  [SignatureScheme.RSA_PKCS1_SHA384, 'rsa_pkcs1_sha384'],
  [SignatureScheme.RSA_PKCS1_SHA512, 'rsa_pkcs1_sha512'],
  [SignatureScheme.RSA_PSS_PSS_SHA256, 'rsa_pss_pss_sha256'],
  [SignatureScheme.RSA_PSS_PSS_SHA384, 'rsa_pss_pss_sha384'],
  [SignatureScheme.RSA_PSS_PSS_SHA512, 'rsa_pss_pss_sha512'],
]);

function buildCipherString(suites: number[]): { ciphers: string; ciphersuites: string } {
  const tls13: string[] = [];
  const tls12: string[] = [];
  for (const s of suites) {
    const name = CIPHER_NAME.get(s);
    if (!name) continue;
    if (name.startsWith('TLS_')) {
      tls13.push(name);
    } else {
      tls12.push(name);
    }
  }
  return {
    ciphers: tls12.join(':'),
    ciphersuites: tls13.join(':'),
  };
}

function buildEcdhCurve(groups: number[]): string {
  return groups
    .map((g) => GROUP_NAME.get(g))
    .filter((n): n is string => n !== undefined)
    .join(':');
}

function buildSigalgs(algs: number[]): string {
  return algs
    .map((a) => SIGALG_NAME.get(a))
    .filter((n): n is string => n !== undefined)
    .join(':');
}

/**
 * TLS engine that delegates to Node.js’s built-in `tls` module. Provides
 * standard TLS connectivity with optional browser-profile cipher and curve
 * configuration, but does not reproduce the exact ClientHello byte sequence
 * of a real browser. Use {@link StealthTLSEngine} when full fingerprint
 * fidelity is required.
 */
export class NodeTLSEngine implements ITLSEngine {
  /**
   * Establishes a TLS connection to the given host and port using Node.js’s
   * native `tls.connect()`. When a `profile` is supplied the cipher list,
   * ECDH curves, and signature algorithms are overridden to match that profile.
   *
   * @param {TLSConnectOptions} options  - Connection parameters.
   * @param {BrowserProfile}    [profile] - Optional browser profile to apply cipher/curve overrides.
   * @returns {Promise<TLSSocket>} Resolves with the connected TLS duplex stream.
   * @throws {TLSError} If the handshake fails, times out, or the connection is aborted.
   */
  async connect(
    options: TLSConnectOptions,
    profile?: BrowserProfile,
  ): Promise<TLSSocket> {
    return new Promise<TLSSocket>((resolve, reject) => {
      const tlsOpts: tls.ConnectionOptions = {
        host: options.host,
        port: options.port,
        servername: options.servername ?? options.host,
        rejectUnauthorized: !options.insecure,
        ALPNProtocols: options.alpnProtocols,
        minVersion: 'TLSv1.2',
        maxVersion: 'TLSv1.3',
      };

      if (options.family !== undefined) {
        (tlsOpts as Record<string, unknown>)['family'] = options.family;
      }

      if (profile) {
        const { ciphers, ciphersuites } = buildCipherString(profile.tls.cipherSuites);
        tlsOpts.ciphers = ciphers;
        (tlsOpts as Record<string, unknown>)['cipherSuites'] = ciphersuites;
        tlsOpts.ecdhCurve = buildEcdhCurve(profile.tls.supportedGroups);
        tlsOpts.sigalgs = buildSigalgs(profile.tls.signatureAlgorithms);
        tlsOpts.ALPNProtocols = profile.tls.alpnProtocols;
      }

      if (options.socket) {
        tlsOpts.socket = options.socket as net.Socket;
      }

      const timeoutMs = options.timeout ?? 30_000;

      const socket = tls.connect(tlsOpts);

      let settled = false;
      let timer: ReturnType<typeof setTimeout> | undefined;

      if (timeoutMs > 0) {
        timer = setTimeout(() => {
          if (!settled) {
            settled = true;
            socket.destroy();
            reject(new TLSError('TLS handshake timed out'));
          }
        }, timeoutMs);
      }

      if (options.signal) {
        const onAbort = () => {
          if (!settled) {
            settled = true;
            if (timer) clearTimeout(timer);
            socket.destroy();
            reject(new TLSError('TLS connection aborted'));
          }
        };
        if (options.signal.aborted) {
          onAbort();
          return;
        }
        options.signal.addEventListener('abort', onAbort, { once: true });
      }

      socket.once('secureConnect', () => {
        if (settled) return;
        settled = true;
        if (timer) clearTimeout(timer);

        const cipher = socket.getCipher();
        const proto = socket.getProtocol();

        const connectionInfo: TLSConnectionInfo = {
          version: proto ?? 'unknown',
          alpnProtocol: socket.alpnProtocol || null,
          cipher: cipher?.name ?? 'unknown',
        };

        const tlsSocket: TLSSocket = Object.assign(socket as unknown as Duplex, {
          connectionInfo,
          destroyTLS(): void {
            socket.destroy();
          },
        }) as TLSSocket;

        resolve(tlsSocket);
      });

      socket.once('error', (err: Error) => {
        if (settled) return;
        settled = true;
        if (timer) clearTimeout(timer);
        const e = err as NodeJS.ErrnoException & { reason?: string };
        const message = err.message || [e.code, e.reason].filter(Boolean).join(': ') || 'TLS handshake failed';
        reject(new TLSError(message));
      });
    });
  }
}
