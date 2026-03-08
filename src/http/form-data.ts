import { randomBytes } from "node:crypto";

/** File attachment for multipart form-data encoding. */
export interface FormFile {
  /** Raw file content. */
  data: Buffer;
  /** Name of the file. */
  filename: string;
  /** MIME content type (defaults to application/octet-stream). */
  contentType?: string;
}

/** A form field value — either a plain string or a file attachment. */
export type FormValue = string | FormFile;

/** Multipart form-data encoder for HTTP request bodies. */
export class FormData {
  private readonly fields: Array<{ name: string; value: FormValue }> = [];
  private readonly boundary: string;

  /** Create a new FormData instance with a random boundary. */
  constructor() {
    this.boundary = `----NLcURL${randomBytes(24).toString("hex")}`;
  }

  /**
   * Append a field to the form.
   *
   * @param {string} name - Field name.
   * @param {FormValue} value - String value or file attachment.
   * @returns {this} This instance for chaining.
   */
  append(name: string, value: FormValue): this {
    this.fields.push({ name, value });
    return this;
  }

  /** Content-Type header value including the boundary parameter. */
  get contentType(): string {
    return `multipart/form-data; boundary=${this.boundary}`;
  }

  /**
   * Return the multipart boundary string.
   *
   * @returns {string} The boundary delimiter.
   */
  getBoundary(): string {
    return this.boundary;
  }

  /**
   * Encode all fields into a multipart form-data buffer.
   *
   * @returns {Buffer} Wire-format multipart body.
   */
  encode(): Buffer {
    const parts: Buffer[] = [];
    const CRLF = "\r\n";

    for (const { name, value } of this.fields) {
      parts.push(Buffer.from(`--${this.boundary}${CRLF}`, "utf-8"));

      if (typeof value === "string") {
        parts.push(Buffer.from(`Content-Disposition: form-data; name="${escapeQuotes(name)}"${CRLF}`, "utf-8"));
        parts.push(Buffer.from(CRLF, "utf-8"));
        parts.push(Buffer.from(value, "utf-8"));
      } else {
        const filename = escapeQuotes(value.filename);
        const contentType = value.contentType ?? "application/octet-stream";
        parts.push(Buffer.from(`Content-Disposition: form-data; name="${escapeQuotes(name)}"; filename="${filename}"${CRLF}`, "utf-8"));
        parts.push(Buffer.from(`Content-Type: ${contentType}${CRLF}`, "utf-8"));
        parts.push(Buffer.from(CRLF, "utf-8"));
        parts.push(value.data);
      }

      parts.push(Buffer.from(CRLF, "utf-8"));
    }

    parts.push(Buffer.from(`--${this.boundary}--${CRLF}`, "utf-8"));

    return Buffer.concat(parts);
  }
}

function escapeQuotes(str: string): string {
  return str
    .replace(/[\r\n\0]/g, "")
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"');
}
