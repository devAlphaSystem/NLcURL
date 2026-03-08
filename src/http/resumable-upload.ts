/** State of a resumable upload session. */
export interface UploadSession {
  /** Server-assigned upload URL. */
  uploadUrl: string;
  /** Number of bytes already uploaded. */
  offset: number;
  /** Total size of the upload in bytes. */
  totalSize: number;
  /** Whether the upload has been completed. */
  complete: boolean;
  /** Timestamp when the session was created. */
  createdAt: number;
}

/** Configuration for resumable upload operations. */
export interface ResumableUploadConfig {
  /** Size of each upload chunk in bytes. */
  chunkSize?: number;
  /** Maximum number of retry attempts per chunk. */
  maxRetries?: number;
  /** Progress callback invoked after each chunk. */
  onProgress?: (offset: number, total: number) => void;
}

const DEFAULT_CHUNK_SIZE = 5 * 1024 * 1024;
const UPLOAD_CONTENT_TYPE = "application/partial-upload";

/**
 * Build headers for initiating a new resumable upload.
 *
 * @param {number} totalSize - Total upload size in bytes.
 * @param {string} [contentType] - MIME type of the upload content.
 * @returns {Record<string, string>} Header record for the upload creation request.
 */
export function buildUploadCreationHeaders(totalSize: number, contentType?: string): Record<string, string> {
  return {
    "upload-complete": "?0",
    "upload-draft-interop-version": "7",
    "content-type": contentType ?? "application/octet-stream",
    "content-length": String(totalSize),
  };
}

/**
 * Build headers for resuming an upload at a given offset.
 *
 * @param {number} offset - Byte offset to resume from.
 * @param {number} chunkSize - Size of the chunk being sent.
 * @param {boolean} isLast - Whether this is the final chunk.
 * @returns {Record<string, string>} Header record for the resume request.
 */
export function buildUploadResumeHeaders(offset: number, chunkSize: number, isLast: boolean): Record<string, string> {
  return {
    "upload-offset": String(offset),
    "upload-complete": isLast ? "?1" : "?0",
    "upload-draft-interop-version": "7",
    "content-type": UPLOAD_CONTENT_TYPE,
    "content-length": String(chunkSize),
  };
}

/**
 * Build headers for querying the current upload offset.
 *
 * @returns {Record<string, string>} Header record for the offset query request.
 */
export function buildUploadOffsetHeaders(): Record<string, string> {
  return {
    "upload-draft-interop-version": "7",
  };
}

/**
 * Parse the upload offset from response headers.
 *
 * @param {Record<string, string>} headers - Response headers.
 * @returns {number} Byte offset, or -1 if not present or invalid.
 */
export function parseUploadOffset(headers: Record<string, string>): number {
  const val = headers["upload-offset"];
  if (!val) return -1;
  const offset = parseInt(val, 10);
  return Number.isFinite(offset) && offset >= 0 ? offset : -1;
}

/**
 * Check whether the upload is marked as complete in response headers.
 *
 * @param {Record<string, string>} headers - Response headers.
 * @returns {boolean} `true` if the upload-complete header is "?1".
 */
export function isUploadComplete(headers: Record<string, string>): boolean {
  const val = headers["upload-complete"];
  return val === "?1";
}

/**
 * Split a buffer into offset-chunk pairs for resumable upload.
 *
 * @param {Buffer} data - Data to split.
 * @param {number} [chunkSize] - Maximum chunk size in bytes.
 * @returns {Array<[number, Buffer]>} Array of [offset, chunk] tuples.
 */
export function splitIntoChunks(data: Buffer, chunkSize?: number): Array<[number, Buffer]> {
  const size = chunkSize ?? DEFAULT_CHUNK_SIZE;
  const chunks: Array<[number, Buffer]> = [];
  let offset = 0;
  while (offset < data.length) {
    const end = Math.min(offset + size, data.length);
    chunks.push([offset, data.subarray(offset, end)]);
    offset = end;
  }
  return chunks;
}

/**
 * Extract the upload URL from response headers.
 *
 * @param {Record<string, string>} headers - Response headers.
 * @param {string} requestUrl - Original request URL for resolving relative locations.
 * @returns {string | null} Absolute upload URL, or `null` if not present.
 */
export function parseUploadUrl(headers: Record<string, string>, requestUrl: string): string | null {
  const location = headers["location"];
  if (!location) return null;
  try {
    return new URL(location, requestUrl).href;
  } catch {
    return null;
  }
}
