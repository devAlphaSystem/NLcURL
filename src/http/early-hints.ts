/** Parsed early hint from a Link header in a 103 response. */
export interface EarlyHint {
  /** Target resource URI. */
  uri: string;
  /** Link relation type (e.g. "preload"). */
  rel?: string;
  /** Destination type for the resource (e.g. "script", "style"). */
  as?: string;
  /** MIME type of the linked resource. */
  type?: string;
  /** Whether the resource requires CORS. */
  crossorigin?: boolean;
}

/**
 * Parse a Link header into an array of early hints.
 *
 * @param {string} linkHeader - Raw Link header value.
 * @returns {EarlyHint[]} Array of parsed early hint objects.
 */
export function parseLinkHeader(linkHeader: string): EarlyHint[] {
  const hints: EarlyHint[] = [];

  const parts = linkHeader.split(",");
  for (const part of parts) {
    const trimmed = part.trim();
    const uriMatch = /^<([^>]+)>/.exec(trimmed);
    if (!uriMatch) continue;

    const hint: EarlyHint = { uri: uriMatch[1]! };

    const params = trimmed.substring(uriMatch[0].length);
    const relMatch = /;\s*rel\s*=\s*"?([^";]+)"?/i.exec(params);
    if (relMatch) hint.rel = relMatch[1]!.trim();

    const asMatch = /;\s*as\s*=\s*"?([^";]+)"?/i.exec(params);
    if (asMatch) hint.as = asMatch[1]!.trim();

    const typeMatch = /;\s*type\s*=\s*"?([^";]+)"?/i.exec(params);
    if (typeMatch) hint.type = typeMatch[1]!.trim();

    if (/;\s*crossorigin/i.test(params)) {
      hint.crossorigin = true;
    }

    hints.push(hint);
  }

  return hints;
}

/** Callback invoked when 103 Early Hints are received. */
export type EarlyHintsCallback = (hints: EarlyHint[]) => void;
