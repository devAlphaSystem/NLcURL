/**
 * The result of parsing a `nlcurl` command-line invocation. Every flag has a
 * default value so the object is always fully defined; only fields affected by
 * the user's arguments differ from the defaults.
 *
 * @typedef  {Object}               ParsedArgs
 * @property {string}               url             - Request URL.
 * @property {string}               method          - HTTP method (default: `"GET"`).
 * @property {Array<[string,string]>} headers        - Request headers in `[name, value]` pairs.
 * @property {string | null}        data            - Request body string (`-d` / `--data`).
 * @property {string | null}        dataRaw         - Raw request body string (`--data-raw`).
 * @property {string | null}        output          - File path to write the response body to.
 * @property {string | null}        impersonate     - Browser profile name for fingerprint impersonation.
 * @property {string | null}        ja3             - Custom JA3 fingerprint string.
 * @property {string | null}        akamai          - Custom Akamai HTTP/2 fingerprint string.
 * @property {boolean}              stealth         - Use stealth TLS engine.
 * @property {string | null}        proxy           - Proxy URL.
 * @property {string | null}        proxyAuth       - Proxy credentials (`user:password`).
 * @property {boolean}              insecure        - Skip TLS certificate verification.
 * @property {boolean}              followRedirects - Follow HTTP redirects (default: `true`).
 * @property {number}               maxRedirects    - Maximum number of redirects to follow.
 * @property {number}               timeout         - Request timeout in milliseconds.
 * @property {string | null}        httpVersion     - Force HTTP version (`"1.1"` or `"2"`).
 * @property {boolean}              verbose         - Print verbose request/response details.
 * @property {boolean}              silent          - Suppress all non-critical output.
 * @property {boolean}              compressed      - Request and accept compressed responses.
 * @property {boolean}              head            - Send a HEAD request.
 * @property {boolean}              include         - Include response headers in output.
 * @property {boolean}              listProfiles    - Print available browser profiles and exit.
 * @property {boolean}              help            - Print help text and exit.
 * @property {boolean}              version         - Print version string and exit.
 * @property {string | null}        cookies         - Cookie string to send with the request.
 * @property {string | null}        cookieJar       - Path to a Netscape-format cookie jar file.
 * @property {string | null}        userAgent       - Override the User-Agent header.
 */
export interface ParsedArgs {
  url: string;
  method: string;
  headers: Array<[string, string]>;
  data: string | null;
  dataRaw: string | null;
  output: string | null;
  impersonate: string | null;
  ja3: string | null;
  akamai: string | null;
  stealth: boolean;
  proxy: string | null;
  proxyAuth: string | null;
  insecure: boolean;
  followRedirects: boolean;
  maxRedirects: number;
  timeout: number;
  httpVersion: string | null;
  verbose: boolean;
  silent: boolean;
  compressed: boolean;
  head: boolean;
  include: boolean;
  listProfiles: boolean;
  help: boolean;
  version: boolean;
  cookies: string | null;
  cookieJar: string | null;
  userAgent: string | null;
}

const DEFAULTS: ParsedArgs = {
  url: "",
  method: "GET",
  headers: [],
  data: null,
  dataRaw: null,
  output: null,
  impersonate: null,
  ja3: null,
  akamai: null,
  stealth: false,
  proxy: null,
  proxyAuth: null,
  insecure: false,
  followRedirects: true,
  maxRedirects: 20,
  timeout: 30000,
  httpVersion: null,
  verbose: false,
  silent: false,
  compressed: false,
  head: false,
  include: false,
  listProfiles: false,
  help: false,
  version: false,
  cookies: null,
  cookieJar: null,
  userAgent: null,
};

/**
 * Parses `nlcurl` command-line arguments from `argv` into a structured
 * `ParsedArgs` object. Unknown flags are silently ignored.
 *
 * @param {string[]} argv - Raw process argument vector (typically `process.argv`).
 * @returns {ParsedArgs} Parsed argument object with defaults applied for omitted flags.
 */
export function parseArgs(argv: string[]): ParsedArgs {
  const result: ParsedArgs = { ...DEFAULTS, headers: [] };
  const args = argv.slice(2);
  let i = 0;

  while (i < args.length) {
    const arg = args[i]!;

    if (arg.startsWith("--") && arg.includes("=")) {
      const eqIdx = arg.indexOf("=");
      const flag = arg.substring(0, eqIdx);
      const value = arg.substring(eqIdx + 1);
      processLongFlag(flag, value, result);
      i++;
      continue;
    }

    switch (arg) {
      case "-X":
      case "--request":
        result.method = requireNext(args, ++i, arg).toUpperCase();
        break;

      case "-H":
      case "--header": {
        const raw = requireNext(args, ++i, arg);
        const colonIdx = raw.indexOf(":");
        if (colonIdx > 0) {
          result.headers.push([raw.substring(0, colonIdx).trim(), raw.substring(colonIdx + 1).trim()]);
        }
        break;
      }

      case "-d":
      case "--data":
      case "--data-ascii":
        result.data = requireNext(args, ++i, arg);
        if (result.method === "GET") result.method = "POST";
        break;

      case "--data-raw":
        result.dataRaw = requireNext(args, ++i, arg);
        if (result.method === "GET") result.method = "POST";
        break;

      case "-A":
      case "--user-agent":
        result.userAgent = requireNext(args, ++i, arg);
        break;

      case "-o":
      case "--output":
        result.output = requireNext(args, ++i, arg);
        break;

      case "-I":
      case "--head":
        result.head = true;
        result.method = "HEAD";
        break;

      case "-i":
      case "--include":
        result.include = true;
        break;

      case "-v":
      case "--verbose":
        result.verbose = true;
        break;

      case "-s":
      case "--silent":
        result.silent = true;
        break;

      case "--compressed":
        result.compressed = true;
        break;

      case "--impersonate":
        result.impersonate = requireNext(args, ++i, arg);
        break;

      case "--ja3":
        result.ja3 = requireNext(args, ++i, arg);
        break;

      case "--akamai":
        result.akamai = requireNext(args, ++i, arg);
        break;

      case "--stealth":
        result.stealth = true;
        break;

      case "--list-profiles":
        result.listProfiles = true;
        break;

      case "-x":
      case "--proxy":
        result.proxy = requireNext(args, ++i, arg);
        break;

      case "-U":
      case "--proxy-user":
        result.proxyAuth = requireNext(args, ++i, arg);
        break;

      case "-k":
      case "--insecure":
        result.insecure = true;
        break;

      case "-L":
      case "--location":
        result.followRedirects = true;
        break;

      case "--no-location":
        result.followRedirects = false;
        break;

      case "--max-redirs":
        result.maxRedirects = parseInt(requireNext(args, ++i, arg), 10);
        break;

      case "-m":
      case "--max-time":
        result.timeout = Math.round(parseFloat(requireNext(args, ++i, arg)) * 1000);
        break;

      case "--http1.1":
        result.httpVersion = "1.1";
        break;

      case "--http2":
        result.httpVersion = "2";
        break;

      case "-b":
      case "--cookie":
        result.cookies = requireNext(args, ++i, arg);
        break;

      case "-c":
      case "--cookie-jar":
        result.cookieJar = requireNext(args, ++i, arg);
        break;

      case "-h":
      case "--help":
        result.help = true;
        break;

      case "-V":
      case "--version":
        result.version = true;
        break;

      default:
        if (!arg.startsWith("-") && !result.url) {
          result.url = arg;
        }
        break;
    }

    i++;
  }

  return result;
}

function requireNext(args: string[], idx: number, flag: string): string {
  if (idx >= args.length) {
    throw new Error(`Flag ${flag} requires a value`);
  }
  return args[idx]!;
}

function processLongFlag(flag: string, value: string, result: ParsedArgs): void {
  switch (flag) {
    case "--impersonate":
      result.impersonate = value;
      break;
    case "--ja3":
      result.ja3 = value;
      break;
    case "--akamai":
      result.akamai = value;
      break;
    case "--proxy":
      result.proxy = value;
      break;
    case "--proxy-user":
      result.proxyAuth = value;
      break;
    case "--max-redirs":
      result.maxRedirects = parseInt(value, 10);
      break;
    case "--max-time":
      result.timeout = Math.round(parseFloat(value) * 1000);
      break;
    case "--output":
      result.output = value;
      break;
    case "--request":
      result.method = value.toUpperCase();
      break;
    case "--user-agent":
      result.userAgent = value;
      break;
    case "--cookie":
      result.cookies = value;
      break;
    case "--cookie-jar":
      result.cookieJar = value;
      break;
    case "--header": {
      const colonIdx = value.indexOf(":");
      if (colonIdx > 0) {
        result.headers.push([value.substring(0, colonIdx).trim(), value.substring(colonIdx + 1).trim()]);
      }
      break;
    }
    case "--data":
    case "--data-ascii":
      result.data = value;
      if (result.method === "GET") result.method = "POST";
      break;
    case "--data-raw":
      result.dataRaw = value;
      if (result.method === "GET") result.method = "POST";
      break;
    default:
      break;
  }
}
