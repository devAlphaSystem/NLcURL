import { createHash, createHmac, createECDH, createVerify, X509Certificate, createCipheriv, createDecipheriv, type CipherGCMTypes, type KeyObject } from "node:crypto";
import { rootCertificates } from "node:tls";
import * as net from "node:net";
import { BufferReader } from "../../utils/buffer-reader.js";
import { BufferWriter } from "../../utils/buffer-writer.js";
import { RecordType, HandshakeType, ProtocolVersion, AlertDescription, SignatureScheme } from "../constants.js";
import { TLSError } from "../../core/errors.js";
import { readRecord, writeRecord, type TLSRecord } from "./record-layer.js";
import type { KeyShareEntry } from "./client-hello.js";
import type { AEADAlgorithm } from "./record-layer.js";
import type { HandshakeResult } from "./handshake.js";
import { verifyPinnedPublicKey } from "../pin-verification.js";

interface TLS12CipherInfo {
  kx: "ECDHE";
  auth: "RSA" | "ECDSA";
  aead: AEADAlgorithm;
  hash: "sha256" | "sha384";
  keyLen: number;
  ivLen: number;
  isAEAD: true;
}

function tls12CipherInfo(suite: number): TLS12CipherInfo | null {
  switch (suite) {
    case 0xc02f:
      return { kx: "ECDHE", auth: "RSA", aead: "aes-128-gcm", hash: "sha256", keyLen: 16, ivLen: 4, isAEAD: true };
    case 0xc030:
      return { kx: "ECDHE", auth: "RSA", aead: "aes-256-gcm", hash: "sha384", keyLen: 32, ivLen: 4, isAEAD: true };
    case 0xc02b:
      return { kx: "ECDHE", auth: "ECDSA", aead: "aes-128-gcm", hash: "sha256", keyLen: 16, ivLen: 4, isAEAD: true };
    case 0xc02c:
      return { kx: "ECDHE", auth: "ECDSA", aead: "aes-256-gcm", hash: "sha384", keyLen: 32, ivLen: 4, isAEAD: true };
    case 0xcca8:
      return { kx: "ECDHE", auth: "RSA", aead: "chacha20-poly1305", hash: "sha256", keyLen: 32, ivLen: 12, isAEAD: true };
    case 0xcca9:
      return { kx: "ECDHE", auth: "ECDSA", aead: "chacha20-poly1305", hash: "sha256", keyLen: 32, ivLen: 12, isAEAD: true };
    default:
      return null;
  }
}

function tls12CipherName(suite: number): string {
  switch (suite) {
    case 0xc02f:
      return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
    case 0xc030:
      return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";
    case 0xc02b:
      return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
    case 0xc02c:
      return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
    case 0xcca8:
      return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256";
    case 0xcca9:
      return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256";
    default:
      return "unknown";
  }
}

function pHash(alg: string, secret: Buffer, seed: Buffer, length: number): Buffer {
  const result = Buffer.alloc(length);
  let a = seed;
  let offset = 0;
  while (offset < length) {
    a = Buffer.from(createHmac(alg, secret).update(a).digest());
    const output = Buffer.from(
      createHmac(alg, secret)
        .update(Buffer.concat([a, seed]))
        .digest(),
    );
    const toCopy = Math.min(output.length, length - offset);
    output.copy(result, offset, 0, toCopy);
    offset += toCopy;
  }
  return result;
}

function tls12PRF(alg: "sha256" | "sha384", secret: Buffer, label: string, seed: Buffer, length: number): Buffer {
  const labelBuf = Buffer.from(label, "ascii");
  const fullSeed = Buffer.concat([labelBuf, seed]);
  return pHash(alg, secret, fullSeed, length);
}

const CURVE_NIDS: Record<number, string> = {
  0x0017: "prime256v1",
  0x0018: "secp384r1",
  0x0019: "secp521r1",
};

interface ECDHEParams {
  curveId: number;
  serverPublicKey: Buffer;
  signatureScheme: number;
  signature: Buffer;
  signedParams: Buffer;
}

function parseServerKeyExchange(body: Buffer): ECDHEParams {
  const r = new BufferReader(body);
  const curveType = r.readUInt8();
  if (curveType !== 3) throw new TLSError("Expected named_curve in ServerKeyExchange");
  const paramsStart = 0;
  const curveId = r.readUInt16();
  const pubLen = r.readUInt8();
  const serverPublicKey = Buffer.from(r.readBytes(pubLen));
  const signedParams = body.subarray(paramsStart, r.position);

  const signatureScheme = r.readUInt16();
  const sigLen = r.readUInt16();
  const signature = Buffer.from(r.readBytes(sigLen));

  return { curveId, serverPublicKey, signatureScheme, signature, signedParams };
}

function parseTLS12CertificateMessage(body: Buffer): Buffer[] {
  const r = new BufferReader(body);
  const certs: Buffer[] = [];
  const listLen = (r.readUInt8() << 16) | (r.readUInt8() << 8) | r.readUInt8();
  const listEnd = r.position + listLen;
  while (r.position < listEnd) {
    const certLen = (r.readUInt8() << 16) | (r.readUInt8() << 8) | r.readUInt8();
    const certData = Buffer.from(r.readBytes(certLen));
    certs.push(certData);
  }
  return certs;
}

function verifyCertificateChain(certs: Buffer[], hostname: string): void {
  if (certs.length === 0) throw new TLSError("Server sent empty certificate chain");
  const x509Certs = certs.map((der) => new X509Certificate(der));
  const leafCert = x509Certs[0]!;
  if (!leafCert.checkHost(hostname)) throw new TLSError(`Certificate hostname mismatch: expected ${hostname}`, AlertDescription.BAD_CERTIFICATE);
  const now = new Date();
  if (now < new Date(leafCert.validFrom) || now > new Date(leafCert.validTo)) throw new TLSError("Certificate has expired or is not yet valid", AlertDescription.CERTIFICATE_EXPIRED);
  const trustedRoots = rootCertificates.map((pem) => new X509Certificate(pem));
  for (let i = 0; i < x509Certs.length - 1; i++) {
    const cert = x509Certs[i]!;
    const issuer = x509Certs[i + 1]!;
    if (!cert.checkIssued(issuer)) throw new TLSError("Certificate chain verification failed: issuer mismatch", AlertDescription.UNKNOWN_CA);
  }
  const topCert = x509Certs[x509Certs.length - 1]!;
  const isTrusted = trustedRoots.some((root) => {
    try {
      return topCert.checkIssued(root) || topCert.fingerprint === root.fingerprint;
    } catch {
      return false;
    }
  });
  const leafTrusted = trustedRoots.some((root) => {
    try {
      return leafCert.fingerprint === root.fingerprint;
    } catch {
      return false;
    }
  });
  if (!isTrusted && !leafTrusted) throw new TLSError("Certificate chain does not terminate at a trusted root CA", AlertDescription.UNKNOWN_CA);
}

function socketWrite(socket: net.Socket, data: Buffer): Promise<void> {
  return new Promise((resolve, reject) => {
    socket.write(data, (err) => {
      if (err) reject(new TLSError(err.message));
      else resolve();
    });
  });
}

function readHandshakeRecord(socket: net.Socket): Promise<TLSRecord> {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    let settled = false;
    const onData = (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      tryParse();
    };
    const onError = (err: Error) => {
      if (!settled) {
        settled = true;
        cleanup();
        reject(new TLSError(err.message));
      }
    };
    const onClose = () => {
      if (!settled) {
        settled = true;
        cleanup();
        reject(new TLSError("Connection closed during handshake"));
      }
    };
    const cleanup = () => {
      socket.removeListener("data", onData);
      socket.removeListener("error", onError);
      socket.removeListener("close", onClose);
    };
    const tryParse = () => {
      const result = readRecord(buffer, 0);
      if (result) {
        settled = true;
        cleanup();
        if (result.bytesRead < buffer.length) socket.unshift(buffer.subarray(result.bytesRead));
        resolve(result.record);
      }
    };
    socket.on("data", onData);
    socket.once("error", onError);
    socket.once("close", onClose);
    tryParse();
  });
}

const AEAD_TAG_SIZE = 16;

interface TLS12RecordCrypto {
  encrypt(seqNum: bigint, contentType: number, plaintext: Buffer): Buffer;
  decrypt(seqNum: bigint, contentType: number, ciphertext: Buffer): Buffer;
}

function buildGCMNonce(implicitIV: Buffer, explicitNonce: Buffer): Buffer {
  return Buffer.concat([implicitIV, explicitNonce]);
}

function buildChaCha20Nonce(iv: Buffer, seqNum: bigint): Buffer {
  const nonce = Buffer.from(iv);
  const seqBuf = Buffer.alloc(8);
  seqBuf.writeBigUInt64BE(seqNum);
  for (let i = 0; i < 8; i++) {
    nonce[nonce.length - 8 + i]! ^= seqBuf[i]!;
  }
  return nonce;
}

function buildTLS12AAD(seqNum: bigint, contentType: number, version: number, length: number): Buffer {
  const aad = Buffer.alloc(13);
  aad.writeBigUInt64BE(seqNum, 0);
  aad[8] = contentType;
  aad.writeUInt16BE(version, 9);
  aad.writeUInt16BE(length, 11);
  return aad;
}

function createTLS12RecordCrypto(aead: AEADAlgorithm, key: Buffer, iv: Buffer): TLS12RecordCrypto {
  const isChaCha = aead === "chacha20-poly1305";

  return {
    encrypt(seqNum: bigint, contentType: number, plaintext: Buffer): Buffer {
      let nonce: Buffer;
      let prefix: Buffer;

      if (isChaCha) {
        nonce = buildChaCha20Nonce(iv, seqNum);
        prefix = Buffer.alloc(0);
      } else {
        const explicitNonce = Buffer.alloc(8);
        explicitNonce.writeBigUInt64BE(seqNum);
        nonce = buildGCMNonce(iv, explicitNonce);
        prefix = explicitNonce;
      }

      const aad = buildTLS12AAD(seqNum, contentType, ProtocolVersion.TLS_1_2, plaintext.length);
      const cipher = createCipheriv(aead as CipherGCMTypes, key, nonce, { authTagLength: AEAD_TAG_SIZE });
      cipher.setAAD(aad);
      const encrypted = cipher.update(plaintext);
      const final = cipher.final();
      const tag = cipher.getAuthTag();
      return Buffer.concat([prefix, encrypted, final, tag]);
    },

    decrypt(seqNum: bigint, contentType: number, ciphertext: Buffer): Buffer {
      let nonce: Buffer;
      let encData: Buffer;

      if (isChaCha) {
        nonce = buildChaCha20Nonce(iv, seqNum);
        encData = ciphertext;
      } else {
        if (ciphertext.length < 8 + AEAD_TAG_SIZE) throw new TLSError("TLS 1.2 record too short for GCM");
        const explicitNonce = ciphertext.subarray(0, 8);
        nonce = buildGCMNonce(iv, explicitNonce);
        encData = ciphertext.subarray(8);
      }

      if (encData.length < AEAD_TAG_SIZE) throw new TLSError("TLS 1.2 record too short for AEAD tag");
      const encryptedData = encData.subarray(0, encData.length - AEAD_TAG_SIZE);
      const tag = encData.subarray(encData.length - AEAD_TAG_SIZE);

      const plaintextLen = encryptedData.length;
      const aad = buildTLS12AAD(seqNum, contentType, ProtocolVersion.TLS_1_2, plaintextLen);

      const decipher = createDecipheriv(aead as CipherGCMTypes, key, nonce, { authTagLength: AEAD_TAG_SIZE });
      decipher.setAAD(aad);
      decipher.setAuthTag(tag);
      try {
        const decrypted = decipher.update(encryptedData);
        const final = decipher.final();
        return Buffer.concat([decrypted, final]);
      } catch {
        throw new TLSError("TLS 1.2 AEAD decryption failed");
      }
    },
  };
}

function verifyServerKeyExchange(params: ECDHEParams, serverPublicKeyObj: ReturnType<typeof import("node:crypto").createPublicKey>, clientRandom: Buffer, serverRandom: Buffer): void {
  const sigAlg = signatureAlgorithmForScheme(params.signatureScheme);
  if (!sigAlg) throw new TLSError(`Unsupported signature scheme in ServerKeyExchange: 0x${params.signatureScheme.toString(16)}`);

  const signedData = Buffer.concat([clientRandom, serverRandom, params.signedParams]);
  const verifier = createVerify(sigAlg.algorithm || "SHA256");
  verifier.update(signedData);

  const verifyOptions: { key: KeyObject; padding?: number; saltLength?: number } = { key: serverPublicKeyObj };
  if (sigAlg.padding !== undefined) {
    verifyOptions.padding = sigAlg.padding;
    verifyOptions.saltLength = sigAlg.saltLength;
  }

  if (!verifier.verify(verifyOptions, params.signature)) {
    throw new TLSError("ServerKeyExchange signature verification failed");
  }
}

function signatureAlgorithmForScheme(scheme: number): { algorithm: string; padding?: number; saltLength?: number } | null {
  switch (scheme) {
    case SignatureScheme.ECDSA_SECP256R1_SHA256:
      return { algorithm: "SHA256" };
    case SignatureScheme.ECDSA_SECP384R1_SHA384:
      return { algorithm: "SHA384" };
    case SignatureScheme.ECDSA_SECP521R1_SHA512:
      return { algorithm: "SHA512" };
    case SignatureScheme.RSA_PSS_RSAE_SHA256:
    case SignatureScheme.RSA_PSS_PSS_SHA256:
      return { algorithm: "SHA256", padding: 6, saltLength: 32 };
    case SignatureScheme.RSA_PSS_RSAE_SHA384:
    case SignatureScheme.RSA_PSS_PSS_SHA384:
      return { algorithm: "SHA384", padding: 6, saltLength: 48 };
    case SignatureScheme.RSA_PSS_RSAE_SHA512:
    case SignatureScheme.RSA_PSS_PSS_SHA512:
      return { algorithm: "SHA512", padding: 6, saltLength: 64 };
    case SignatureScheme.RSA_PKCS1_SHA256:
      return { algorithm: "SHA256" };
    case SignatureScheme.RSA_PKCS1_SHA384:
      return { algorithm: "SHA384" };
    case SignatureScheme.RSA_PKCS1_SHA512:
      return { algorithm: "SHA512" };
    case SignatureScheme.RSA_PKCS1_SHA1:
      return { algorithm: "SHA1" };
    default:
      return null;
  }
}

/** Context state for a TLS 1.2 handshake. */
export interface TLS12HandshakeContext {
  /** Client random bytes from the ClientHello. */
  clientRandom: Buffer;
  /** Server random bytes from the ServerHello. */
  serverRandom: Buffer;
  /** Negotiated cipher suite identifier. */
  cipherSuite: number;
  /** Key share entries generated during ClientHello construction. */
  keyShares: KeyShareEntry[];
  /** Server hostname for SNI and certificate verification. */
  hostname: string;
  /** Skip certificate chain validation. */
  insecure: boolean;
  /** Optional SPKI pin(s) for public-key pinning. */
  pinnedPublicKey?: string | string[];
}

/**
 * Complete a TLS 1.2 handshake using ECDHE key exchange.
 *
 * @param {net.Socket} socket - Connected TCP socket.
 * @param {TLS12HandshakeContext} ctx - Handshake context from the ServerHello.
 * @param {Buffer[]} handshakeMessages - Accumulated handshake messages so far.
 * @returns {Promise<HandshakeResult>} Handshake result with negotiated keys and metadata.
 */
export async function performTLS12Handshake(socket: net.Socket, ctx: TLS12HandshakeContext, handshakeMessages: Buffer[]): Promise<HandshakeResult> {
  const info = tls12CipherInfo(ctx.cipherSuite);
  if (!info) throw new TLSError(`Unsupported TLS 1.2 cipher suite: 0x${ctx.cipherSuite.toString(16)}`);

  const prfAlg = info.hash;
  let serverCertificates: Buffer[] = [];
  let serverPublicKeyObj: ReturnType<typeof import("node:crypto").createPublicKey> | null = null;
  let ecdhParams: ECDHEParams | null = null;
  let gotServerHelloDone = false;

  const allHandshakeMessages = [...handshakeMessages];

  while (!gotServerHelloDone) {
    const record = await readHandshakeRecord(socket);

    if (record.type === RecordType.ALERT) {
      const desc = record.fragment.length >= 2 ? record.fragment[1] : 0;
      throw new TLSError(`Server alert during TLS 1.2 handshake: ${desc}`, desc);
    }

    if (record.type !== RecordType.HANDSHAKE) {
      throw new TLSError(`Unexpected record type in TLS 1.2 handshake: ${record.type}`);
    }

    let offset = 0;
    while (offset < record.fragment.length) {
      if (record.fragment.length - offset < 4) break;
      const msgType = record.fragment[offset]!;
      const msgLen = (record.fragment[offset + 1]! << 16) | (record.fragment[offset + 2]! << 8) | record.fragment[offset + 3]!;
      const msgEnd = offset + 4 + msgLen;
      if (msgEnd > record.fragment.length) break;

      const fullMsg = record.fragment.subarray(offset, msgEnd);
      allHandshakeMessages.push(Buffer.from(fullMsg));

      const msgBody = record.fragment.subarray(offset + 4, msgEnd);

      switch (msgType) {
        case HandshakeType.CERTIFICATE: {
          serverCertificates = parseTLS12CertificateMessage(msgBody);
          if (serverCertificates.length > 0) {
            const x509 = new X509Certificate(serverCertificates[0]!);
            serverPublicKeyObj = x509.publicKey;
          }
          if (!ctx.insecure) {
            verifyCertificateChain(serverCertificates, ctx.hostname);
          }
          if (ctx.pinnedPublicKey && serverCertificates.length > 0) {
            verifyPinnedPublicKey(serverCertificates[0]!, ctx.pinnedPublicKey);
          }
          break;
        }
        case 12: {
          ecdhParams = parseServerKeyExchange(msgBody);
          if (!ctx.insecure && serverPublicKeyObj) {
            verifyServerKeyExchange(ecdhParams, serverPublicKeyObj, ctx.clientRandom, ctx.serverRandom);
          }
          break;
        }
        case 14: {
          gotServerHelloDone = true;
          break;
        }
        default:
          break;
      }

      offset = msgEnd;
    }
  }

  if (!ecdhParams) throw new TLSError("Server did not send ServerKeyExchange");

  const curveName = CURVE_NIDS[ecdhParams.curveId];
  if (!curveName) throw new TLSError(`Unsupported curve in ServerKeyExchange: 0x${ecdhParams.curveId.toString(16)}`);

  const ecdh = createECDH(curveName);
  ecdh.generateKeys();
  const clientPubKey = Buffer.from(ecdh.getPublicKey());
  const preMasterSecret = Buffer.from(ecdh.computeSecret(ecdhParams.serverPublicKey));

  const ckeBody = new BufferWriter(1 + clientPubKey.length);
  ckeBody.writeUInt8(clientPubKey.length);
  ckeBody.writeBytes(clientPubKey);
  const ckeMsg = wrapHandshakeMessage(16, ckeBody.toBuffer());
  allHandshakeMessages.push(ckeMsg);

  const ckeRecord = writeRecord(RecordType.HANDSHAKE, ProtocolVersion.TLS_1_2, ckeMsg);
  await socketWrite(socket, ckeRecord);

  const seed = Buffer.concat([ctx.clientRandom, ctx.serverRandom]);
  const masterSecret = tls12PRF(prfAlg, preMasterSecret, "master secret", seed, 48);

  const keyBlockLen = (info.keyLen + info.ivLen) * 2;
  const keySeed = Buffer.concat([ctx.serverRandom, ctx.clientRandom]);
  const keyBlock = tls12PRF(prfAlg, masterSecret, "key expansion", keySeed, keyBlockLen);

  let kbOffset = 0;
  const clientWriteKey = keyBlock.subarray(kbOffset, kbOffset + info.keyLen);
  kbOffset += info.keyLen;
  const serverWriteKey = keyBlock.subarray(kbOffset, kbOffset + info.keyLen);
  kbOffset += info.keyLen;
  const clientWriteIV = keyBlock.subarray(kbOffset, kbOffset + info.ivLen);
  kbOffset += info.ivLen;
  const serverWriteIV = keyBlock.subarray(kbOffset, kbOffset + info.ivLen);

  const ccsRecord = writeRecord(RecordType.CHANGE_CIPHER_SPEC, ProtocolVersion.TLS_1_2, Buffer.from([1]));
  await socketWrite(socket, ccsRecord);

  const clientCrypto = createTLS12RecordCrypto(info.aead, clientWriteKey, clientWriteIV);

  const transcriptForFinished = Buffer.concat(allHandshakeMessages);
  const transcriptHash = createHash(prfAlg).update(transcriptForFinished).digest();
  const clientVerifyData = tls12PRF(prfAlg, masterSecret, "client finished", transcriptHash, 12);

  const finishedMsg = wrapHandshakeMessage(HandshakeType.FINISHED, clientVerifyData);
  allHandshakeMessages.push(finishedMsg);

  const encryptedFinished = clientCrypto.encrypt(0n, RecordType.HANDSHAKE, finishedMsg);
  const finishedRecord = writeRecord(RecordType.APPLICATION_DATA, ProtocolVersion.TLS_1_2, encryptedFinished);
  await socketWrite(socket, finishedRecord);

  let serverSeq = 0n;
  const serverCrypto = createTLS12RecordCrypto(info.aead, serverWriteKey, serverWriteIV);
  let gotServerFinished = false;

  while (!gotServerFinished) {
    const record = await readHandshakeRecord(socket);

    if (record.type === RecordType.CHANGE_CIPHER_SPEC) {
      continue;
    }

    if (record.type === RecordType.ALERT) {
      const desc = record.fragment.length >= 2 ? record.fragment[1] : 0;
      throw new TLSError(`Server alert: ${desc}`, desc);
    }

    if (record.type === RecordType.APPLICATION_DATA) {
      const plaintext = serverCrypto.decrypt(serverSeq++, RecordType.HANDSHAKE, record.fragment);

      if (plaintext.length < 4) throw new TLSError("Malformed server Finished");
      const msgType = plaintext[0]!;
      if (msgType !== HandshakeType.FINISHED) throw new TLSError("Expected server Finished");
      const serverVerifyData = plaintext.subarray(4);

      const serverTranscriptHash = createHash(prfAlg).update(Buffer.concat(allHandshakeMessages)).digest();
      const expectedServerVerify = tls12PRF(prfAlg, masterSecret, "server finished", serverTranscriptHash, 12);
      if (!serverVerifyData.equals(expectedServerVerify)) {
        throw new TLSError("Server Finished verify_data mismatch");
      }
      gotServerFinished = true;
    }
  }

  return {
    alpnProtocol: null,
    cipher: tls12CipherName(ctx.cipherSuite),
    version: "TLSv1.2",
    clientKey: Buffer.from(clientWriteKey),
    clientIV: Buffer.from(clientWriteIV),
    serverKey: Buffer.from(serverWriteKey),
    serverIV: Buffer.from(serverWriteIV),
    aead: info.aead,
  };
}

function wrapHandshakeMessage(type: number, body: Buffer): Buffer {
  const msg = Buffer.alloc(4 + body.length);
  msg[0] = type;
  msg[1] = (body.length >> 16) & 0xff;
  msg[2] = (body.length >> 8) & 0xff;
  msg[3] = body.length & 0xff;
  body.copy(msg, 4);
  return msg;
}
