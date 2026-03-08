/** TLS record content type identifiers. */
export const RecordType = {
  CHANGE_CIPHER_SPEC: 20,
  ALERT: 21,
  HANDSHAKE: 22,
  APPLICATION_DATA: 23,
} as const;

/** TLS protocol version numbers. */
export const ProtocolVersion = {
  TLS_1_0: 0x0301,
  TLS_1_1: 0x0302,
  TLS_1_2: 0x0303,
  TLS_1_3: 0x0304,
} as const;

/** TLS handshake message type identifiers. */
export const HandshakeType = {
  CLIENT_HELLO: 1,
  SERVER_HELLO: 2,
  NEW_SESSION_TICKET: 4,
  END_OF_EARLY_DATA: 5,
  ENCRYPTED_EXTENSIONS: 8,
  CERTIFICATE: 11,
  CERTIFICATE_REQUEST: 13,
  CERTIFICATE_VERIFY: 15,
  FINISHED: 20,
  KEY_UPDATE: 24,
  MESSAGE_HASH: 254,
} as const;

/** TLS cipher suite numeric identifiers. */
export const CipherSuite = {
  TLS_AES_128_GCM_SHA256: 0x1301,
  TLS_AES_256_GCM_SHA384: 0x1302,
  TLS_CHACHA20_POLY1305_SHA256: 0x1303,

  TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: 0xc02b,
  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: 0xc02f,
  TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: 0xc02c,
  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: 0xc030,
  TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: 0xcca9,
  TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: 0xcca8,
  TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: 0xc013,
  TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: 0xc014,
  TLS_RSA_WITH_AES_128_GCM_SHA256: 0x009c,
  TLS_RSA_WITH_AES_256_GCM_SHA384: 0x009d,
  TLS_RSA_WITH_AES_128_CBC_SHA: 0x002f,
  TLS_RSA_WITH_AES_256_CBC_SHA: 0x0035,

  TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: 0xc009,
  TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: 0xc00a,
} as const;

/** TLS extension type numeric identifiers. */
export const ExtensionType = {
  SERVER_NAME: 0x0000,
  EC_POINT_FORMATS: 0x000b,
  SUPPORTED_GROUPS: 0x000a,
  SESSION_TICKET: 0x0023,
  ENCRYPT_THEN_MAC: 0x0016,
  EXTENDED_MASTER_SECRET: 0x0017,
  SIGNATURE_ALGORITHMS: 0x000d,
  SUPPORTED_VERSIONS: 0x002b,
  PSK_KEY_EXCHANGE_MODES: 0x002d,
  KEY_SHARE: 0x0033,
  RENEGOTIATION_INFO: 0xff01,
  STATUS_REQUEST: 0x0005,
  SIGNED_CERTIFICATE_TIMESTAMP: 0x0012,
  APPLICATION_LAYER_PROTOCOL_NEGOTIATION: 0x0010,
  COMPRESS_CERTIFICATE: 0x001b,
  TOKEN_BINDING: 0x0018,
  APPLICATION_SETTINGS: 0x4469,
  DELEGATED_CREDENTIALS: 0x0022,
  RECORD_SIZE_LIMIT: 0x001c,
  PADDING: 0x0015,
  PRE_SHARED_KEY: 0x0029,
  EARLY_DATA: 0x002a,
  ENCRYPTED_CLIENT_HELLO: 0xfe0d,
  POST_HANDSHAKE_AUTH: 0x0031,
} as const;

/** TLS supported named groups (curves and key exchange). */
export const NamedGroup = {
  X25519: 0x001d,
  SECP256R1: 0x0017,
  SECP384R1: 0x0018,
  SECP521R1: 0x0019,
  X448: 0x001e,
  FFDHE2048: 0x0100,
  FFDHE3072: 0x0101,
  X25519_KYBER768: 0x6399,
  X25519_MLKEM768: 0x4588,
} as const;

/** TLS signature scheme identifiers. */
export const SignatureScheme = {
  ECDSA_SECP256R1_SHA256: 0x0403,
  ECDSA_SECP384R1_SHA384: 0x0503,
  ECDSA_SECP521R1_SHA512: 0x0603,
  RSA_PSS_RSAE_SHA256: 0x0804,
  RSA_PSS_RSAE_SHA384: 0x0805,
  RSA_PSS_RSAE_SHA512: 0x0806,
  RSA_PKCS1_SHA256: 0x0401,
  RSA_PKCS1_SHA384: 0x0501,
  RSA_PKCS1_SHA512: 0x0601,
  ED25519: 0x0807,
  ED448: 0x0808,
  RSA_PSS_PSS_SHA256: 0x0809,
  RSA_PSS_PSS_SHA384: 0x080a,
  RSA_PSS_PSS_SHA512: 0x080b,
  RSA_PKCS1_SHA1: 0x0201,
  ECDSA_SHA1: 0x0203,
} as const;

/** Elliptic curve point format identifiers. */
export const ECPointFormat = {
  UNCOMPRESSED: 0,
} as const;

/** Pre-shared key exchange mode identifiers. */
export const PskKeyExchangeMode = {
  PSK_KE: 0,
  PSK_DHE_KE: 1,
} as const;

/** Certificate compression algorithm identifiers. */
export const CertCompressAlg = {
  ZLIB: 1,
  BROTLI: 2,
  ZSTD: 3,
} as const;

/** Standard GREASE (Generate Random Extensions And Sustain Extensibility) values. */
export const GREASE_VALUES: readonly number[] = [0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa];

/**
 * Select a deterministic GREASE value from a seed.
 *
 * @param {number} seed - Numeric seed for index selection.
 * @returns {number} GREASE value from the standard set.
 */
export function greaseValue(seed: number): number {
  return GREASE_VALUES[seed % GREASE_VALUES.length]!;
}

/** TLS alert description codes. */
export const AlertDescription = {
  CLOSE_NOTIFY: 0,
  UNEXPECTED_MESSAGE: 10,
  BAD_RECORD_MAC: 20,
  RECORD_OVERFLOW: 22,
  HANDSHAKE_FAILURE: 40,
  BAD_CERTIFICATE: 42,
  CERTIFICATE_EXPIRED: 45,
  CERTIFICATE_UNKNOWN: 46,
  ILLEGAL_PARAMETER: 47,
  UNKNOWN_CA: 48,
  DECODE_ERROR: 50,
  DECRYPT_ERROR: 51,
  PROTOCOL_VERSION: 70,
  INSUFFICIENT_SECURITY: 71,
  INTERNAL_ERROR: 80,
  NO_RENEGOTIATION: 100,
  MISSING_EXTENSION: 109,
  UNRECOGNIZED_NAME: 112,
  CERTIFICATE_REQUIRED: 116,
} as const;
