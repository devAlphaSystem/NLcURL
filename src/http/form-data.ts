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
    const CRLF_BUF = Buffer.from("\r\n", "utf-8");
    const boundaryLine = Buffer.from(`--${this.boundary}\r\n`, "utf-8");
    const boundaryEnd = Buffer.from(`--${this.boundary}--\r\n`, "utf-8");

    for (const { name, value } of this.fields) {
      parts.push(boundaryLine);

      if (typeof value === "string") {
        parts.push(Buffer.from(`Content-Disposition: form-data; name="${escapeQuotes(name)}"\r\n`, "utf-8"));
        parts.push(CRLF_BUF);
        parts.push(Buffer.from(value, "utf-8"));
      } else {
        const filename = escapeQuotes(value.filename);
        const contentType = value.contentType ?? "application/octet-stream";
        parts.push(Buffer.from(`Content-Disposition: form-data; name="${escapeQuotes(name)}"; filename="${filename}"\r\n`, "utf-8"));
        parts.push(Buffer.from(`Content-Type: ${contentType}\r\n`, "utf-8"));
        parts.push(CRLF_BUF);
        parts.push(value.data);
      }

      parts.push(CRLF_BUF);
    }

    parts.push(boundaryEnd);

    return Buffer.concat(parts);
  }
}

function escapeQuotes(str: string): string {
  return str
    .replace(/[\r\n\0]/g, "")
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"');
}
