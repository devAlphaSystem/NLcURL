import { randomBytes } from "node:crypto";

/**
 * Represents a single form field value. Either a string or a file descriptor.
 */
export interface FormFile {
  /** The file content as a Buffer. */
  data: Buffer;
  /** The filename to use in the Content-Disposition header. */
  filename: string;
  /** The MIME type of the file. Defaults to `application/octet-stream`. */
  contentType?: string;
}

export type FormValue = string | FormFile;

/**
 * Builds a `multipart/form-data` request body per RFC 7578.
 *
 * Generates a cryptographically random boundary and serializes all fields
 * into a single `Buffer` suitable for use as a request body. The
 * corresponding `Content-Type` header (including the boundary parameter)
 * is available via {@link FormData.contentType}.
 *
 * @example
 * ```ts
 * const form = new FormData();
 * form.append("username", "alice");
 * form.append("avatar", { data: avatarBuffer, filename: "avatar.png", contentType: "image/png" });
 *
 * const response = await post("https://example.com/upload", form);
 * ```
 */
export class FormData {
  private readonly fields: Array<{ name: string; value: FormValue }> = [];
  private readonly boundary: string;

  constructor() {
    this.boundary = `----NLcURL${randomBytes(24).toString("hex")}`;
  }

  /**
   * Appends a field to the form data.
   *
   * @param {string}    name  - The field name.
   * @param {FormValue} value - A string value or a {@link FormFile} descriptor.
   * @returns {this} The `FormData` instance for chaining.
   */
  append(name: string, value: FormValue): this {
    this.fields.push({ name, value });
    return this;
  }

  /**
   * Returns the `Content-Type` header value including the boundary parameter.
   * Must be set on the request for the server to parse the body correctly.
   */
  get contentType(): string {
    return `multipart/form-data; boundary=${this.boundary}`;
  }

  /**
   * Returns the boundary string used for this form data instance.
   */
  getBoundary(): string {
    return this.boundary;
  }

  /**
   * Serializes all appended fields into a single `Buffer` in
   * `multipart/form-data` format per RFC 7578.
   *
   * @returns {Buffer} The encoded multipart body.
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

/**
 * Escapes double quotes and backslashes in header parameter values
 * and strips control characters (\r, \n, \0) to prevent header injection
 * in Content-Disposition fields.
 */
function escapeQuotes(str: string): string {
  return str
    .replace(/[\r\n\0]/g, "")
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"');
}
