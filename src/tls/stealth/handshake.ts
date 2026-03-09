import { createHash, createECDH, diffieHellman, createPublicKey, createPrivateKey, createVerify, verify as cryptoVerify, X509Certificate, timingSafeEqual, type KeyObject } from "node:crypto";
import { rootCertificates } from "node:tls";
import * as net from "node:net";
import { BufferReader } from "../../utils/buffer-reader.js";
import { BufferWriter } from "../../utils/buffer-writer.js";
import { RecordType, HandshakeType, ProtocolVersion, CipherSuite, NamedGroup, AlertDescription, SignatureScheme } from "../constants.js";
import { TLSError } from "../../core/errors.js";
import type { BrowserProfile } from "../../fingerprints/types.js";
import { buildClientHello, buildClientHelloWithECH, generateKeyShare, type ClientHelloResult, type ClientHelloECHResult, type KeyShareEntry } from "./client-hello.js";
import { readRecord, writeRecord, wrapEncryptedRecord, unwrapEncryptedRecord, type AEADAlgorithm, type TLSRecord } from "./record-layer.js";
import { type HashAlgorithm, hkdfExtract, hkdfExpandLabel, deriveHandshakeKeys, deriveApplicationKeys, keyIVLengths, computeFinishedVerifyData, deriveSecret } from "./key-schedule.js";
import { performTLS12Handshake, type TLS12HandshakeContext } from "./tls12-handshake.js";
import { verifyPinnedPublicKey } from "../pin-verification.js";
import type { ECHEncryptionParams } from "../ech.js";

function isTLS13CipherSuite(suite: number): boolean {
  return suite >= 0x1300 && suite <= 0x13ff;
}

function cipherToHash(suite: number): HashAlgorithm {
  switch (suite) {
    case CipherSuite.TLS_AES_256_GCM_SHA384:
      return "sha384";
    default:
      return "sha256";
  }
}

function cipherToAEAD(suite: number): AEADAlgorithm {
  switch (suite) {
    case CipherSuite.TLS_AES_128_GCM_SHA256:
      return "aes-128-gcm";
    case CipherSuite.TLS_AES_256_GCM_SHA384:
      return "aes-256-gcm";
    case CipherSuite.TLS_CHACHA20_POLY1305_SHA256:
      return "chacha20-poly1305";
    default:
      return "aes-128-gcm";
  }
}

function cipherName(suite: number): string {
  switch (suite) {
    case CipherSuite.TLS_AES_128_GCM_SHA256:
      return "TLS_AES_128_GCM_SHA256";
    case CipherSuite.TLS_AES_256_GCM_SHA384:
      return "TLS_AES_256_GCM_SHA384";
    case CipherSuite.TLS_CHACHA20_POLY1305_SHA256:
      return "TLS_CHACHA20_POLY1305_SHA256";
    default:
      return "unknown";
  }
}

function computeSharedSecret(serverGroup: number, serverPublicKey: Buffer, clientKeyShares: KeyShareEntry[]): Buffer {
  const clientKS = clientKeyShares.find((ks) => ks.group === serverGroup);
  if (!clientKS) {
    throw new TLSError(`Server selected group 0x${serverGroup.toString(16)} but we did not offer it`);
  }

  switch (serverGroup) {
    case NamedGroup.X25519: {
      const privKey = createPrivateKey({
        key: buildX25519PKCS8(clientKS.privateKey),
        format: "der",
        type: "pkcs8",
      });
      const pubKey = createPublicKey({
        key: buildX25519SPKI(serverPublicKey),
        format: "der",
        type: "spki",
      });
      return Buffer.from(diffieHellman({ privateKey: privKey, publicKey: pubKey }));
    }
    case NamedGroup.SECP256R1:
    case NamedGroup.SECP384R1:
    case NamedGroup.SECP521R1: {
      const curveName = serverGroup === NamedGroup.SECP256R1 ? "prime256v1" : serverGroup === NamedGroup.SECP384R1 ? "secp384r1" : "secp521r1";
      const ecdh = createECDH(curveName);
      ecdh.setPrivateKey(clientKS.privateKey);
      return Buffer.from(ecdh.computeSecret(serverPublicKey));
    }
    default:
      throw new TLSError(`Unsupported key exchange group: 0x${serverGroup.toString(16)}`);
  }
}

function buildX25519PKCS8(rawPrivate: Buffer): Buffer {
  const header = Buffer.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20]);
  return Buffer.concat([header, rawPrivate]);
}

function buildX25519SPKI(rawPublic: Buffer): Buffer {
  const header = Buffer.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00]);
  return Buffer.concat([header, rawPublic]);
}

/** State machine phases of the TLS handshake. */
export enum HandshakeState {
  Initial,
  WaitingServerHello,
  WaitingEncryptedExtensions,
  WaitingCertificate,
  WaitingCertificateVerify,
  WaitingFinished,
  Connected,
  Failed,
}

/** Result of a completed TLS handshake containing negotiated parameters and keys. */
export interface HandshakeResult {
  /** Negotiated ALPN protocol, or `null`. */
  alpnProtocol: string | null;
  /** Negotiated cipher suite name. */
  cipher: string;
  /** Negotiated TLS version string. */
  version: string;
  /** Client application traffic key. */
  clientKey: Buffer;
  /** Client application traffic IV. */
  clientIV: Buffer;
  /** Server application traffic key. */
  serverKey: Buffer;
  /** Server application traffic IV. */
  serverIV: Buffer;
  /** Negotiated AEAD algorithm. */
  aead: AEADAlgorithm;
  /** Server application traffic secret (for KeyUpdate). */
  serverTrafficSecret?: Buffer;
  /** Client application traffic secret (for KeyUpdate). */
  clientTrafficSecret?: Buffer;
  /** Hash algorithm used during handshake (for KeyUpdate). */
  hashAlgorithm?: HashAlgorithm;
  /** Master secret for resumption derivation. */
  masterSecret?: Buffer;
  /** Transcript hash after client Finished (for resumption master secret). */
  clientFinishedHash?: Buffer;
}

/**
 * Perform a full TLS handshake over a raw TCP socket.
 *
 * Handles TLS 1.3 (and falls back to TLS 1.2) using the custom
 * stealth engine for fingerprint-accurate ClientHello construction.
 *
 * @param {net.Socket} socket - Connected TCP socket.
 * @param {BrowserProfile} profile - Browser profile controlling extension and cipher order.
 * @param {string} hostname - Server hostname for SNI and certificate verification.
 * @param {boolean} insecure - Skip certificate chain validation.
 * @param {string|string[]} [pinnedPublicKey] - Optional SPKI pin(s) to verify.
 * @param {ECHEncryptionParams} [echParams] - Optional ECH encryption parameters.
 * @returns {Promise<HandshakeResult>} Handshake result with traffic keys and connection metadata.
 */
export async function performHandshake(socket: net.Socket, profile: BrowserProfile, hostname: string, insecure: boolean, pinnedPublicKey?: string | string[], echParams?: ECHEncryptionParams): Promise<HandshakeResult> {
  let clientHello: ClientHelloResult;
  let echResult: ClientHelloECHResult | null = null;

  if (echParams) {
    echResult = buildClientHelloWithECH(profile, hostname, echParams);
    clientHello = echResult;
  } else {
    clientHello = buildClientHello(profile, hostname);
  }

  await socketWrite(socket, clientHello.record);

  const _hashAlg: HashAlgorithm = "sha256";
  let transcriptHash = createHash("sha256");

  if (echResult) {
    transcriptHash.update(echResult.innerHandshakeMessage);
  } else {
    transcriptHash.update(clientHello.handshakeMessage);
  }

  let outerTranscriptHash: ReturnType<typeof createHash> | null = null;
  if (echResult) {
    outerTranscriptHash = createHash("sha256");
    outerTranscriptHash.update(clientHello.handshakeMessage);
  }

  const serverHelloRecord = await readHandshakeRecord(socket);
  if (serverHelloRecord.type !== RecordType.HANDSHAKE) {
    if (serverHelloRecord.type === RecordType.ALERT) {
      const alertLevel = serverHelloRecord.fragment[0];
      const alertDesc = serverHelloRecord.fragment[1];
      throw new TLSError(`Server sent alert: level=${alertLevel} desc=${alertDesc}`, alertDesc);
    }
    throw new TLSError("Expected Handshake record, got type " + serverHelloRecord.type);
  }

  const shReader = new BufferReader(serverHelloRecord.fragment);
  const shType = shReader.readUInt8();
  if (shType !== HandshakeType.SERVER_HELLO) {
    throw new TLSError("Expected ServerHello, got handshake type " + shType);
  }

  const shLength = shReader.readUInt24();
  const shBody = shReader.readBytes(shLength);

  let echAccepted = false;
  if (echResult) {
    echAccepted = checkECHAcceptConfirmation(echResult.innerHandshakeMessage, serverHelloRecord.fragment, shBody);
    if (!echAccepted) {
      transcriptHash = outerTranscriptHash!;
    }
  }
  outerTranscriptHash = null;

  transcriptHash.update(serverHelloRecord.fragment);

  const sh = parseServerHello(shBody);

  const isTLS12 = sh.selectedVersion === ProtocolVersion.TLS_1_2 && !isTLS13CipherSuite(sh.cipherSuite);

  if (isTLS12) {
    let alpnFromSH: string | null = null;
    {
      const shBodyReader = new BufferReader(shBody);
      shBodyReader.readBytes(2);
      shBodyReader.readBytes(32);
      const sidLen = shBodyReader.readUInt8();
      shBodyReader.readBytes(sidLen);
      shBodyReader.readBytes(2);
      shBodyReader.readBytes(1);
      if (shBodyReader.remaining > 0) {
        const extLen = shBodyReader.readUInt16();
        const extEnd = shBodyReader.position + extLen;
        while (shBodyReader.position < extEnd) {
          const extType = shBodyReader.readUInt16();
          const extDataLen = shBodyReader.readUInt16();
          const extData = shBodyReader.readBytes(extDataLen);
          if (extType === 0x0010) {
            const alpnR = new BufferReader(extData);
            const listLen = alpnR.readUInt16();
            if (listLen > 0) {
              const protoLen = alpnR.readUInt8();
              alpnFromSH = alpnR.readBytes(protoLen).toString("ascii");
            }
          }
        }
      }
    }

    const ctx: TLS12HandshakeContext = {
      clientRandom: clientHello.clientRandom,
      serverRandom: sh.serverRandom,
      cipherSuite: sh.cipherSuite,
      keyShares: clientHello.keyShares,
      hostname,
      insecure,
      pinnedPublicKey,
    };

    const handshakeMessages = [clientHello.handshakeMessage, serverHelloRecord.fragment];
    const result = await performTLS12Handshake(socket, ctx, handshakeMessages);
    result.alpnProtocol = alpnFromSH;
    return result;
  }

  const negotiatedHash = cipherToHash(sh.cipherSuite);
  if (negotiatedHash !== "sha256") {
    transcriptHash = createHash(negotiatedHash);
    transcriptHash.update(clientHello.handshakeMessage);
    transcriptHash.update(serverHelloRecord.fragment);
  }

  const HRR_RANDOM = Buffer.from("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c", "hex");

  if (sh.serverRandom.equals(HRR_RANDOM)) {
    const ch1Hash = Buffer.from(transcriptHash.copy().digest());
    transcriptHash = createHash(negotiatedHash);
    const syntheticMsg = Buffer.alloc(4 + ch1Hash.length);
    syntheticMsg[0] = 254;
    syntheticMsg[1] = 0;
    syntheticMsg[2] = 0;
    syntheticMsg[3] = ch1Hash.length;
    ch1Hash.copy(syntheticMsg, 4);
    transcriptHash.update(syntheticMsg);
    transcriptHash.update(serverHelloRecord.fragment);

    const requestedGroup = sh.keyShareGroup;
    if (requestedGroup === 0) {
      throw new TLSError("HelloRetryRequest without key_share extension");
    }

    const newKeyShare = generateKeyShare(requestedGroup);
    if (!newKeyShare) {
      throw new TLSError(`Cannot satisfy HelloRetryRequest: unsupported group 0x${requestedGroup.toString(16)}`);
    }

    const newProfile = { ...profile, tls: { ...profile.tls, keyShareGroups: [requestedGroup] } };
    const ch2 = buildClientHello(newProfile, hostname);
    clientHello = { ...ch2, keyShares: [newKeyShare] };

    transcriptHash.update(ch2.handshakeMessage);
    await socketWrite(socket, ch2.record);

    const sh2Record = await readHandshakeRecord(socket);
    if (sh2Record.type !== RecordType.HANDSHAKE) {
      throw new TLSError("Expected ServerHello after HRR, got type " + sh2Record.type);
    }
    const sh2Reader = new BufferReader(sh2Record.fragment);
    const sh2Type = sh2Reader.readUInt8();
    if (sh2Type !== HandshakeType.SERVER_HELLO) {
      throw new TLSError("Expected ServerHello after HRR, got handshake type " + sh2Type);
    }
    const sh2Length = sh2Reader.readUInt24();
    const sh2Body = sh2Reader.readBytes(sh2Length);
    const sh2 = parseServerHello(sh2Body);

    if (sh2.serverRandom.equals(HRR_RANDOM)) {
      throw new TLSError("Received second HelloRetryRequest");
    }

    transcriptHash.update(sh2Record.fragment);

    Object.assign(sh, sh2);
  }

  const aead = cipherToAEAD(sh.cipherSuite);
  const { keyLen, ivLen } = keyIVLengths(cipherName(sh.cipherSuite));

  const sharedSecret = computeSharedSecret(sh.keyShareGroup, sh.keySharePublicKey, clientHello.keyShares);

  const helloHash = Buffer.from(transcriptHash.copy().digest());
  const handshakeKeys = deriveHandshakeKeys(negotiatedHash, sharedSecret, helloHash, keyLen, ivLen);

  let serverSeq = 0n;
  let alpnProtocol: string | null = null;
  let gotFinished = false;

  let serverCertificates: Buffer[] = [];
  let serverPublicKeyObj: ReturnType<typeof createPublicKey> | null = null;

  while (!gotFinished) {
    const record = await readHandshakeRecord(socket);

    if (record.type === RecordType.CHANGE_CIPHER_SPEC) {
      continue;
    }

    if (record.type === RecordType.ALERT) {
      const desc = record.fragment.length >= 2 ? record.fragment[1] : 0;
      throw new TLSError(`Server alert during handshake: ${desc}`, desc);
    }

    if (record.type !== RecordType.APPLICATION_DATA) {
      throw new TLSError(`Unexpected record type during handshake: ${record.type}`);
    }

    const decrypted = unwrapEncryptedRecord(aead, handshakeKeys.serverHandshakeKey, handshakeKeys.serverHandshakeIV, serverSeq++, record);

    if (decrypted.contentType !== RecordType.HANDSHAKE) {
      if (decrypted.contentType === RecordType.ALERT) {
        throw new TLSError("Server sent encrypted alert");
      }
      continue;
    }

    let offset = 0;
    while (offset < decrypted.plaintext.length) {
      if (decrypted.plaintext.length - offset < 4) break;
      const msgType = decrypted.plaintext[offset]!;
      const msgLen = (decrypted.plaintext[offset + 1]! << 16) | (decrypted.plaintext[offset + 2]! << 8) | decrypted.plaintext[offset + 3]!;
      const msgEnd = offset + 4 + msgLen;
      if (msgEnd > decrypted.plaintext.length) break;

      const fullMsg = decrypted.plaintext.subarray(offset, msgEnd);

      if (msgType === HandshakeType.CERTIFICATE_VERIFY) {
        const cvBody = decrypted.plaintext.subarray(offset + 4, msgEnd);
        if (!insecure && serverPublicKeyObj) {
          const preVerifyHash = Buffer.from(transcriptHash.copy().digest());
          verifyCertificateVerifySignature(cvBody, serverPublicKeyObj, preVerifyHash);
        }
        transcriptHash.update(fullMsg);
        offset = msgEnd;
        continue;
      }

      if (msgType === HandshakeType.FINISHED) {
        const serverFinishedData = decrypted.plaintext.subarray(offset + 4, msgEnd);
        const serverHandshakeSecret = deriveSecret(negotiatedHash, handshakeKeys.handshakeSecret, "s hs traffic", helloHash);
        const expectedVerify = computeFinishedVerifyData(negotiatedHash, serverHandshakeSecret, Buffer.from(transcriptHash.copy().digest()));
        if (!timingSafeEqual(serverFinishedData, expectedVerify)) {
          throw new TLSError("Server Finished verify_data mismatch");
        }
        transcriptHash.update(fullMsg);
        gotFinished = true;
        offset = msgEnd;
        continue;
      }

      transcriptHash.update(fullMsg);

      switch (msgType) {
        case HandshakeType.ENCRYPTED_EXTENSIONS: {
          const eeBody = decrypted.plaintext.subarray(offset + 4, msgEnd);
          alpnProtocol = parseEncryptedExtensions(eeBody);
          break;
        }
        case HandshakeType.CERTIFICATE: {
          const certBody = decrypted.plaintext.subarray(offset + 4, msgEnd);
          serverCertificates = parseCertificateMessage(certBody);
          if (serverCertificates.length > 0) {
            const x509 = new X509Certificate(serverCertificates[0]!);
            serverPublicKeyObj = x509.publicKey;
          }
          if (!insecure) {
            verifyCertificateChain(serverCertificates, hostname);
          }
          if (pinnedPublicKey && serverCertificates.length > 0) {
            verifyPinnedPublicKey(serverCertificates[0]!, pinnedPublicKey);
          }
          break;
        }
        default:
          break;
      }

      offset = msgEnd;
    }
  }

  const ccsRecord = writeRecord(RecordType.CHANGE_CIPHER_SPEC, ProtocolVersion.TLS_1_2, Buffer.from([1]));
  await socketWrite(socket, ccsRecord);

  const clientHandshakeSecret = deriveSecret(negotiatedHash, handshakeKeys.handshakeSecret, "c hs traffic", helloHash);
  const finishedHash = Buffer.from(transcriptHash.copy().digest());
  const clientVerifyData = computeFinishedVerifyData(negotiatedHash, clientHandshakeSecret, finishedHash);

  const finishedMsg = new BufferWriter(4 + clientVerifyData.length);
  finishedMsg.writeUInt8(HandshakeType.FINISHED);
  finishedMsg.writeUInt24(clientVerifyData.length);
  finishedMsg.writeBytes(clientVerifyData);
  const finishedMsgBytes = finishedMsg.toBuffer();

  transcriptHash.update(finishedMsgBytes);

  const encryptedFinished = wrapEncryptedRecord(aead, handshakeKeys.clientHandshakeKey, handshakeKeys.clientHandshakeIV, 0n, RecordType.HANDSHAKE, finishedMsgBytes);
  await socketWrite(socket, encryptedFinished);

  const handshakeHash = Buffer.from(transcriptHash.copy().digest());
  const appKeys = deriveApplicationKeys(negotiatedHash, handshakeKeys.masterSecret, handshakeHash, keyLen, ivLen);

  return {
    alpnProtocol,
    cipher: cipherName(sh.cipherSuite),
    version: "TLSv1.3",
    clientKey: appKeys.clientKey,
    clientIV: appKeys.clientIV,
    serverKey: appKeys.serverKey,
    serverIV: appKeys.serverIV,
    aead,
    serverTrafficSecret: appKeys.serverTrafficSecret,
    clientTrafficSecret: appKeys.clientTrafficSecret,
    hashAlgorithm: negotiatedHash,
    masterSecret: handshakeKeys.masterSecret,
    clientFinishedHash: handshakeHash,
  };
}

interface ServerHelloFields {
  serverRandom: Buffer;
  sessionId: Buffer;
  cipherSuite: number;
  keyShareGroup: number;
  keySharePublicKey: Buffer;
  selectedVersion: number;
}

function parseServerHello(body: Buffer): ServerHelloFields {
  const r = new BufferReader(body);

  const serverVersion = r.readUInt16();
  const serverRandom = r.readBytes(32);
  const sessionIdLen = r.readUInt8();
  const sessionId = r.readBytes(sessionIdLen);
  const cipherSuite = r.readUInt16();
  r.readUInt8();

  let keyShareGroup = 0;
  let keySharePublicKey = Buffer.alloc(0);
  let selectedVersion = serverVersion;

  if (r.remaining > 0) {
    const extLen = r.readUInt16();
    const extEnd = r.position + extLen;

    while (r.position < extEnd) {
      const extType = r.readUInt16();
      const extDataLen = r.readUInt16();
      const extData = r.readBytes(extDataLen);

      if (extType === 0x002b) {
        selectedVersion = extData.readUInt16BE(0);
      } else if (extType === 0x0033) {
        const ksReader = new BufferReader(extData);
        keyShareGroup = ksReader.readUInt16();
        const keyLen = ksReader.readUInt16();
        keySharePublicKey = Buffer.from(ksReader.readBytes(keyLen));
      }
    }
  }

  return {
    serverRandom,
    sessionId,
    cipherSuite,
    keyShareGroup,
    keySharePublicKey,
    selectedVersion,
  };
}

function parseEncryptedExtensions(body: Buffer): string | null {
  const r = new BufferReader(body);
  let alpn: string | null = null;

  if (r.remaining < 2) return null;
  const extLen = r.readUInt16();
  const extEnd = r.position + extLen;

  while (r.position < extEnd) {
    const extType = r.readUInt16();
    const extDataLen = r.readUInt16();
    const extData = r.readBytes(extDataLen);

    if (extType === 0x0010) {
      const alpnReader = new BufferReader(extData);
      const listLen = alpnReader.readUInt16();
      if (listLen > 0) {
        const protoLen = alpnReader.readUInt8();
        alpn = alpnReader.readBytes(protoLen).toString("ascii");
      }
    }
  }

  return alpn;
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
        if (result.bytesRead < buffer.length) {
          socket.unshift(buffer.subarray(result.bytesRead));
        }
        resolve(result.record);
      }
    };

    socket.on("data", onData);
    socket.once("error", onError);
    socket.once("close", onClose);

    tryParse();
  });
}

function parseCertificateMessage(body: Buffer): Buffer[] {
  const r = new BufferReader(body);
  const certs: Buffer[] = [];

  const ctxLen = r.readUInt8();
  if (ctxLen > 0) r.readBytes(ctxLen);

  const listLen = (r.readUInt8() << 16) | (r.readUInt8() << 8) | r.readUInt8();
  const listEnd = r.position + listLen;

  while (r.position < listEnd) {
    const certLen = (r.readUInt8() << 16) | (r.readUInt8() << 8) | r.readUInt8();
    const certData = Buffer.from(r.readBytes(certLen));
    certs.push(certData);

    if (r.remaining >= 2) {
      const extLen = r.readUInt16();
      if (extLen > 0) r.readBytes(extLen);
    }
  }

  return certs;
}

function _derWrapCertPublicKey(certDer: Buffer): Buffer {
  const x509 = new X509Certificate(certDer);
  return Buffer.from(x509.publicKey.export({ type: "spki", format: "der" }));
}

/** Maximum certificate chain depth to prevent resource exhaustion attacks. */
const MAX_CHAIN_DEPTH = 10;

function verifyCertificateChain(certs: Buffer[], hostname: string): void {
  if (certs.length === 0) {
    throw new TLSError("Server sent empty certificate chain");
  }

  if (certs.length > MAX_CHAIN_DEPTH) {
    throw new TLSError(`Certificate chain too deep (${certs.length} > ${MAX_CHAIN_DEPTH})`, AlertDescription.BAD_CERTIFICATE);
  }

  const x509Certs = certs.map((der) => new X509Certificate(der));
  const leafCert = x509Certs[0]!;

  if (!leafCert.checkHost(hostname)) {
    throw new TLSError(`Certificate hostname mismatch: expected ${hostname}`, AlertDescription.BAD_CERTIFICATE);
  }

  const now = new Date();
  if (now < new Date(leafCert.validFrom) || now > new Date(leafCert.validTo)) {
    throw new TLSError("Certificate has expired or is not yet valid", AlertDescription.CERTIFICATE_EXPIRED);
  }

  const trustedRoots = rootCertificates.map((pem) => new X509Certificate(pem));

  for (let i = 0; i < x509Certs.length - 1; i++) {
    const cert = x509Certs[i]!;
    const issuer = x509Certs[i + 1]!;
    if (!cert.checkIssued(issuer)) {
      throw new TLSError("Certificate chain verification failed: issuer mismatch", AlertDescription.UNKNOWN_CA);
    }
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

  if (!isTrusted && !leafTrusted) {
    throw new TLSError("Certificate chain does not terminate at a trusted root CA", AlertDescription.UNKNOWN_CA);
  }
}

function signatureAlgorithmForScheme(scheme: number): { algorithm: string; padding?: number; saltLength?: number; isEdDSA?: boolean } | null {
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
    case SignatureScheme.ED25519:
      return { algorithm: "ed25519", isEdDSA: true };
    case SignatureScheme.ED448:
      return { algorithm: "ed448", isEdDSA: true };
    default:
      return null;
  }
}

function verifyCertificateVerifySignature(cvBody: Buffer, serverPublicKey: ReturnType<typeof createPublicKey>, transcriptHashBeforeCV: Buffer): void {
  const r = new BufferReader(cvBody);
  const scheme = r.readUInt16();
  const sigLen = r.readUInt16();
  const signature = Buffer.from(r.readBytes(sigLen));

  const algInfo = signatureAlgorithmForScheme(scheme);
  if (!algInfo) {
    throw new TLSError(`Unsupported CertificateVerify signature scheme: 0x${scheme.toString(16)}`);
  }

  const prefix = Buffer.alloc(64, 0x20);
  const contextString = Buffer.from("TLS 1.3, server CertificateVerify\x00");
  const signedContent = Buffer.concat([prefix, contextString, transcriptHashBeforeCV]);

  if (algInfo.isEdDSA) {
    const ok = cryptoVerify(null, signedContent, serverPublicKey, signature);
    if (!ok) {
      throw new TLSError("CertificateVerify signature verification failed");
    }
    return;
  }

  const verifier = createVerify(algInfo.algorithm || "SHA256");
  verifier.update(signedContent);

  const verifyOptions: { key: KeyObject; padding?: number; saltLength?: number } = { key: serverPublicKey };
  if (algInfo.padding !== undefined) {
    verifyOptions.padding = algInfo.padding;
    verifyOptions.saltLength = algInfo.saltLength;
  }

  if (!verifier.verify(verifyOptions, signature)) {
    throw new TLSError("CertificateVerify signature verification failed");
  }
}

function checkECHAcceptConfirmation(innerCHMsg: Buffer, shFragment: Buffer, shBody: Buffer): boolean {
  if (shBody.length < 34) return false;

  const serverRandom = shBody.subarray(2, 34);
  const confirmation = serverRandom.subarray(24, 32);

  const modifiedFragment = Buffer.from(shFragment);
  modifiedFragment.fill(0, 30, 38);

  const hash = createHash("sha256");
  hash.update(innerCHMsg);
  hash.update(modifiedFragment);
  const transcriptHash = Buffer.from(hash.digest());

  const earlySecret = hkdfExtract("sha256", Buffer.alloc(32), Buffer.alloc(32));

  const expected = hkdfExpandLabel("sha256", earlySecret, "ech accept confirmation", transcriptHash, 8);

  return timingSafeEqual(confirmation, expected);
}
