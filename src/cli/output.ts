
import { NLcURLResponse } from '../core/response.js';
import type { ParsedArgs } from './args.js';

/**
 * Formats the response body (and optionally headers) as a string for CLI output.
 * Includes headers when `args.include` or `args.verbose` is `true`. Returns
 * only headers (no body) when `args.head` is `true`.
 *
 * @param {NLcURLResponse} response - The received response.
 * @param {ParsedArgs}     args     - Parsed CLI arguments controlling output format.
 * @returns {string} Formatted output string ready to print.
 */
export function formatOutput(
  response: NLcURLResponse,
  args: ParsedArgs,
): string {
  const parts: string[] = [];

  if (args.include || args.verbose) {
    parts.push(formatResponseHeaders(response));
    parts.push('');
  }

  if (args.head) {
    return parts.join('\n');
  }

  const body = response.text();
  parts.push(body);

  return parts.join('\n');
}

/**
 * Formats the response status line and headers in the style used by curl's
 * `-i` / `--include` output.
 *
 * @param {NLcURLResponse} response - The response whose headers to format.
 * @returns {string} Multi-line string of the form `HTTP/x.x STATUS\nHeader: value\n...`.
 */
export function formatResponseHeaders(response: NLcURLResponse): string {
  const lines: string[] = [];

  lines.push(`HTTP/${response.httpVersion} ${response.status} ${response.statusText}`);

  for (const [key, value] of Object.entries(response.headers)) {
    lines.push(`${key}: ${value}`);
  }

  return lines.join('\n');
}

/**
 * Formats a verbose outgoing request summary in the style used by curl's `-v`
 * output. Each line is prefixed with `> ` and includes the request line,
 * `Host` header, and all other headers.
 *
 * @param {string}                  method  - HTTP method.
 * @param {string}                  url     - Request URL.
 * @param {Record<string, string>}  headers - Request headers.
 * @returns {string} Verbose request summary string.
 */
export function formatVerboseRequest(
  method: string,
  url: string,
  headers: Record<string, string>,
): string {
  const parsed = new URL(url);
  const lines: string[] = [];

  lines.push(`> ${method} ${parsed.pathname}${parsed.search} HTTP/1.1`);
  lines.push(`> Host: ${parsed.host}`);

  for (const [key, value] of Object.entries(headers)) {
    lines.push(`> ${key}: ${value}`);
  }

  lines.push('>');
  return lines.join('\n');
}

/**
 * Returns the complete help text describing all supported CLI flags and
 * their usage.
 *
 * @returns {string} Help text suitable for printing to stdout.
 */
export function printHelp(): string {
  return `nlcurl -- HTTP client with browser fingerprint impersonation

USAGE:
    nlcurl [OPTIONS] <URL>

OPTIONS:
    -X, --request <METHOD>       HTTP method (GET, POST, PUT, DELETE, etc.)
    -H, --header <HEADER>        Add a request header (Name: Value)
    -d, --data <DATA>            Request body (sets method to POST if not specified)
    --data-raw <DATA>            Request body without special character processing
    -A, --user-agent <AGENT>     Set the User-Agent header
    -o, --output <FILE>          Write response body to file
    -I, --head                   Send HEAD request, show headers only
    -i, --include                Include response headers in output
    -v, --verbose                Verbose output (request and response details)
    -s, --silent                 Suppress progress and error messages
    --compressed                 Request compressed response

IMPERSONATION:
    --impersonate <PROFILE>      Browser profile (e.g. chrome136, firefox138)
    --stealth                    Use stealth TLS engine for full fingerprint control
    --ja3 <FINGERPRINT>          Custom JA3 fingerprint string
    --akamai <FINGERPRINT>       Custom Akamai HTTP/2 fingerprint string
    --list-profiles              List all available browser profiles

CONNECTION:
    -x, --proxy <URL>            Proxy URL (http, socks4, socks5)
    -U, --proxy-user <USER:PASS> Proxy authentication
    -k, --insecure               Skip TLS certificate verification
    -L, --location               Follow redirects (default)
    --no-location                Do not follow redirects
    --max-redirs <NUM>           Maximum number of redirects (default: 20)
    -m, --max-time <SECONDS>     Maximum request time in seconds
    --http1.1                    Force HTTP/1.1
    --http2                      Force HTTP/2

COOKIES:
    -b, --cookie <DATA>          Send cookies (name=value pairs)
    -c, --cookie-jar <FILE>      Write received cookies to file

META:
    -h, --help                   Show this help message
    -V, --version                Show version

EXAMPLES:
    nlcurl https://httpbin.org/get
    nlcurl --impersonate chrome136 https://tls.browserleaks.com/json
    nlcurl --stealth --impersonate firefox138 https://example.com
    nlcurl -X POST -d '{"key":"value"}' -H "Content-Type: application/json" https://api.example.com
    nlcurl -x socks5://127.0.0.1:1080 --impersonate chrome https://ifconfig.me`;
}
