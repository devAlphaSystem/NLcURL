
import crypto from "node:crypto";

function derLength(len) {
  if (len < 0x80) return Buffer.from([len]);
  if (len < 0x100) return Buffer.from([0x81, len]);
  if (len < 0x10000) return Buffer.from([0x82, (len >> 8) & 0xff, len & 0xff]);
  const b = Buffer.alloc(4);
  b.writeUInt32BE(len);
  return Buffer.concat([Buffer.from([0x84]), b]);
}

function derWrap(tag, ...parts) {
  const body = Buffer.concat(parts);
  return Buffer.concat([Buffer.from([tag]), derLength(body.length), body]);
}

const SEQUENCE = 0x30;
const SET = 0x31;
const INTEGER = 0x02;
const BIT_STRING = 0x03;
const OCTET_STRING = 0x04;
const OID = 0x06;
const UTF8_STRING = 0x0c;
const PRINTABLE_STRING = 0x13;
const UTC_TIME = 0x17;
const CONTEXT_0 = 0xa0;
const CONTEXT_3 = 0xa3;

function oid(encodedBytes) {
  return derWrap(OID, Buffer.from(encodedBytes));
}

const OID_CN = [0x55, 0x04, 0x03];
const OID_SHA256_WITH_ECDSA = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const OID_EC_PUBLIC_KEY = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_PRIME256V1 = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_SUBJECT_ALT_NAME = [0x55, 0x1d, 0x11];
const OID_BASIC_CONSTRAINTS = [0x55, 0x1d, 0x13];

export function generateCert() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });

  const keyPem = privateKey.export({ type: "pkcs8", format: "pem" });

  const pubDer = publicKey.export({ type: "spki", format: "der" });
  let pubKeyBits;
  for (let i = 0; i < pubDer.length - 2; i++) {
    if (pubDer[i] === 0x03 && pubDer[i + 1] === 0x42 && pubDer[i + 2] === 0x00) {
      pubKeyBits = pubDer.subarray(i + 3, i + 3 + 65);
      break;
    }
  }
  if (!pubKeyBits) throw new Error("Could not extract public key from SPKI");

  const version = derWrap(CONTEXT_0, derWrap(INTEGER, Buffer.from([0x02]))); 
  const serialNumber = derWrap(INTEGER, Buffer.from([0x01]));
  const signatureAlgorithm = derWrap(SEQUENCE, oid(OID_SHA256_WITH_ECDSA));

  const cnAttr = derWrap(SEQUENCE, oid(OID_CN), derWrap(UTF8_STRING, Buffer.from("localhost")));
  const rdnSequence = derWrap(SEQUENCE, derWrap(SET, cnAttr));

  const now = new Date();
  const notBefore = formatUTCTime(now);
  const notAfterDate = new Date(now);
  notAfterDate.setFullYear(notAfterDate.getFullYear() + 10);
  const notAfter = formatUTCTime(notAfterDate);
  const validity = derWrap(SEQUENCE, derWrap(UTC_TIME, Buffer.from(notBefore)), derWrap(UTC_TIME, Buffer.from(notAfter)));

  const algId = derWrap(SEQUENCE, oid(OID_EC_PUBLIC_KEY), oid(OID_PRIME256V1));
  const pubKeyBitString = derWrap(BIT_STRING, Buffer.from([0x00]), pubKeyBits);
  const subjectPublicKeyInfo = derWrap(SEQUENCE, algId, pubKeyBitString);

  const sanExtension = derWrap(
    SEQUENCE,
    oid(OID_SUBJECT_ALT_NAME),
    derWrap(
      OCTET_STRING,
      derWrap(
        SEQUENCE,
        derWrap(0x82, Buffer.from("localhost")),
        derWrap(0x87, Buffer.from([127, 0, 0, 1])),
      ),
    ),
  );
  const basicConstraints = derWrap(
    SEQUENCE,
    oid(OID_BASIC_CONSTRAINTS),
    derWrap(0x01, Buffer.from([0xff])), 
    derWrap(OCTET_STRING, derWrap(SEQUENCE, derWrap(0x01, Buffer.from([0x00])))),
  );
  const extensions = derWrap(CONTEXT_3, derWrap(SEQUENCE, sanExtension, basicConstraints));

  const tbs = derWrap(
    SEQUENCE,
    version,
    serialNumber,
    signatureAlgorithm,
    rdnSequence, 
    validity,
    rdnSequence, 
    subjectPublicKeyInfo,
    extensions,
  );

  const signer = crypto.createSign("SHA256");
  signer.update(tbs);
  const signature = signer.sign(privateKey);

  const sigBitString = derWrap(BIT_STRING, Buffer.from([0x00]), signature);

  const certificate = derWrap(SEQUENCE, tbs, signatureAlgorithm, sigBitString);

  const certPem = `-----BEGIN CERTIFICATE-----\n${certificate
    .toString("base64")
    .match(/.{1,64}/g)
    .join("\n")}\n-----END CERTIFICATE-----\n`;

  return { key: keyPem, cert: certPem };
}

function formatUTCTime(date) {
  const y = date.getUTCFullYear() % 100;
  const m = String(date.getUTCMonth() + 1).padStart(2, "0");
  const d = String(date.getUTCDate()).padStart(2, "0");
  const h = String(date.getUTCHours()).padStart(2, "0");
  const min = String(date.getUTCMinutes()).padStart(2, "0");
  const s = String(date.getUTCSeconds()).padStart(2, "0");
  return `${String(y).padStart(2, "0")}${m}${d}${h}${min}${s}Z`;
}
