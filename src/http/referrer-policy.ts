/**
 * Referrer-Policy implementation per the W3C Referrer Policy specification.
 * https://www.w3.org/TR/referrer-policy/
 */

/** All supported Referrer-Policy values. */
export type ReferrerPolicy = "no-referrer" | "no-referrer-when-downgrade" | "origin" | "origin-when-cross-origin" | "same-origin" | "strict-origin" | "strict-origin-when-cross-origin" | "unsafe-url";

const VALID_POLICIES = new Set<string>(["no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin", "same-origin", "strict-origin", "strict-origin-when-cross-origin", "unsafe-url"]);

/**
 * Parse a Referrer-Policy header value into a valid policy.
 * If multiple comma-separated values are present, uses the last recognized one (per spec).
 *
 * @param headerValue - Raw Referrer-Policy header value.
 * @returns The resolved policy, or undefined if none recognized.
 */
export function parseReferrerPolicy(headerValue: string): ReferrerPolicy | undefined {
  const tokens = headerValue.split(",").map((t) => t.trim().toLowerCase());
  let last: ReferrerPolicy | undefined;
  for (const token of tokens) {
    if (VALID_POLICIES.has(token)) {
      last = token as ReferrerPolicy;
    }
  }
  return last;
}

/**
 * Compute the Referer header value for a navigation from `from` to `to`
 * using the given referrer policy.
 *
 * @param from - The originating URL.
 * @param to - The destination URL.
 * @param policy - The referrer policy to apply.
 * @returns The Referer header value, or an empty string if suppressed.
 */
export function computeReferrer(from: URL, to: URL, policy: ReferrerPolicy): string {
  const fromOrigin = from.origin;
  const toOrigin = to.origin;
  const sameOrigin = fromOrigin === toOrigin;
  const isDowngrade = from.protocol === "https:" && to.protocol === "http:";

  switch (policy) {
    case "no-referrer":
      return "";

    case "origin":
      return stripToOrigin(from);

    case "unsafe-url":
      return stripFragment(from);

    case "same-origin":
      return sameOrigin ? stripFragment(from) : "";

    case "strict-origin":
      if (isDowngrade) return "";
      return stripToOrigin(from);

    case "no-referrer-when-downgrade":
      if (isDowngrade) return "";
      return stripFragment(from);

    case "origin-when-cross-origin":
      return sameOrigin ? stripFragment(from) : stripToOrigin(from);

    case "strict-origin-when-cross-origin":
      if (isDowngrade) return "";
      return sameOrigin ? stripFragment(from) : stripToOrigin(from);

    default:
      return "";
  }
}

/** Strip URL to origin only (scheme + host + port + /). */
function stripToOrigin(url: URL): string {
  return url.origin + "/";
}

/** Strip fragment from URL, preserving path and query. */
function stripFragment(url: URL): string {
  return url.origin + url.pathname + url.search;
}
