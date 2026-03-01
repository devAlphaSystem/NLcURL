/**
 * CLI output formatting.
 */

import { NLcURLResponse } from '../core/response.js';
import type { ParsedArgs } from './args.js';

/**
 * Format and write response output to stdout/stderr.
 */
export function formatOutput(
  response: NLcURLResponse,
  args: ParsedArgs,
): string {
  const parts: string[] = [];

  // Include response headers (-i / --include)
  if (args.include || args.verbose) {
    parts.push(formatResponseHeaders(response));
    parts.push('');
  }

  // HEAD request: no body
  if (args.head) {
    return parts.join('\n');
  }

  // Body
  const body = response.text();
  parts.push(body);

  return parts.join('\n');
}

/**
 * Format the response status line and headers.
 */
export function formatResponseHeaders(response: NLcURLResponse): string {
  const lines: string[] = [];

  // Status line
  lines.push(`HTTP/${response.httpVersion} ${response.status} ${response.statusText}`);

  // Headers
  for (const [key, value] of Object.entries(response.headers)) {
    lines.push(`${key}: ${value}`);
  }

  return lines.join('\n');
}

/**
 * Format verbose request info (written to stderr).
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
 * Print the help text.
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
