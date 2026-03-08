/**
 * Parsed No-Vary-Search header directive (proposal spec).
 */
export interface NoVarySearchDirective {
  params: boolean | string[];
  except: string[];
  keyOrder: boolean;
}

/**
 * Parses a No-Vary-Search header value into a structured directive.
 *
 * @param {string} header - The raw No-Vary-Search header value.
 * @returns {NoVarySearchDirective|null} The parsed directive, or `null` if the header is empty.
 */
export function parseNoVarySearch(header: string): NoVarySearchDirective | null {
  if (!header) return null;

  const directive: NoVarySearchDirective = {
    params: false,
    except: [],
    keyOrder: false,
  };

  const parts = header.split(",").map((s) => s.trim());

  for (const part of parts) {
    if (part === "params") {
      directive.params = true;
    } else if (part === "key-order") {
      directive.keyOrder = true;
    } else if (part.startsWith("params=")) {
      const listStr = part.substring("params=".length).trim();
      const parsed = parseInnerList(listStr);
      if (parsed) directive.params = parsed;
    } else if (part.startsWith("except=")) {
      const listStr = part.substring("except=".length).trim();
      const parsed = parseInnerList(listStr);
      if (parsed) directive.except = parsed;
    }
  }

  return directive;
}

/**
 * Determines whether two URLs match according to a No-Vary-Search directive.
 *
 * @param {string} cachedUrl - The URL of the cached response.
 * @param {string} requestUrl - The URL of the incoming request.
 * @param {NoVarySearchDirective} directive - The No-Vary-Search directive to apply.
 * @returns {boolean} `true` if the URLs are considered equivalent under the directive.
 */
export function urlsMatchWithNoVarySearch(cachedUrl: string, requestUrl: string, directive: NoVarySearchDirective): boolean {
  let cached: URL;
  let request: URL;
  try {
    cached = new URL(cachedUrl);
    request = new URL(requestUrl);
  } catch {
    return false;
  }

  if (cached.origin !== request.origin) return false;
  if (cached.pathname !== request.pathname) return false;

  const cachedParams = new URLSearchParams(cached.search);
  const requestParams = new URLSearchParams(request.search);

  const filteredCached = filterParams(cachedParams, directive);
  const filteredRequest = filterParams(requestParams, directive);

  if (directive.keyOrder) {
    return paramsEqualUnordered(filteredCached, filteredRequest);
  }

  return paramsEqualOrdered(filteredCached, filteredRequest);
}

/**
 * Normalizes a URL for cache key generation by applying No-Vary-Search filtering.
 *
 * @param {string} url - The URL to normalize.
 * @param {NoVarySearchDirective} directive - The No-Vary-Search directive to apply.
 * @returns {string} The normalized URL string.
 */
export function normalizeUrlForCache(url: string, directive: NoVarySearchDirective): string {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return url;
  }

  const params = new URLSearchParams(parsed.search);
  const filtered = filterParams(params, directive);

  if (directive.keyOrder) {
    filtered.sort();
  }

  parsed.search = filtered.toString();
  return parsed.href;
}

function filterParams(params: URLSearchParams, directive: NoVarySearchDirective): URLSearchParams {
  const result = new URLSearchParams();

  if (directive.params === true) {
    for (const [key, value] of params) {
      if (directive.except.includes(key)) {
        result.append(key, value);
      }
    }
  } else if (Array.isArray(directive.params)) {
    for (const [key, value] of params) {
      if (!directive.params.includes(key)) {
        result.append(key, value);
      }
    }
  } else {
    for (const [key, value] of params) {
      result.append(key, value);
    }
  }

  return result;
}

function paramsEqualUnordered(a: URLSearchParams, b: URLSearchParams): boolean {
  const aEntries = [...a.entries()].sort(([k1, v1], [k2, v2]) => (k1 < k2 ? -1 : k1 > k2 ? 1 : v1 < v2 ? -1 : v1 > v2 ? 1 : 0));
  const bEntries = [...b.entries()].sort(([k1, v1], [k2, v2]) => (k1 < k2 ? -1 : k1 > k2 ? 1 : v1 < v2 ? -1 : v1 > v2 ? 1 : 0));

  if (aEntries.length !== bEntries.length) return false;
  for (let i = 0; i < aEntries.length; i++) {
    if (aEntries[i]![0] !== bEntries[i]![0] || aEntries[i]![1] !== bEntries[i]![1]) {
      return false;
    }
  }
  return true;
}

function paramsEqualOrdered(a: URLSearchParams, b: URLSearchParams): boolean {
  const aEntries = [...a.entries()];
  const bEntries = [...b.entries()];

  if (aEntries.length !== bEntries.length) return false;
  for (let i = 0; i < aEntries.length; i++) {
    if (aEntries[i]![0] !== bEntries[i]![0] || aEntries[i]![1] !== bEntries[i]![1]) {
      return false;
    }
  }
  return true;
}

function parseInnerList(str: string): string[] | null {
  const match = str.match(/^\(([^)]*)\)/);
  if (!match) return null;

  return match[1]!
    .split(/\s+/)
    .map((s) => s.replace(/"/g, "").trim())
    .filter(Boolean);
}
