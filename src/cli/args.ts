/**
 * CLI argument parser.
 *
 * A zero-dependency argv parser tailored for nlcurl flags.
 * Supports long flags (--flag value, --flag=value), short flags (-X GET),
 * and boolean toggles (-k, --insecure).
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
  url: '',
  method: 'GET',
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
 * Parse CLI arguments into structured options.
 */
export function parseArgs(argv: string[]): ParsedArgs {
  const result: ParsedArgs = { ...DEFAULTS, headers: [] };
  const args = argv.slice(2); // Skip node and script path
  let i = 0;

  while (i < args.length) {
    const arg = args[i]!;

    // Handle --flag=value syntax
    if (arg.startsWith('--') && arg.includes('=')) {
      const eqIdx = arg.indexOf('=');
      const flag = arg.substring(0, eqIdx);
      const value = arg.substring(eqIdx + 1);
      processLongFlag(flag, value, result);
      i++;
      continue;
    }

    switch (arg) {
      // ---- Request configuration ----
      case '-X':
      case '--request':
        result.method = requireNext(args, ++i, arg).toUpperCase();
        break;

      case '-H':
      case '--header': {
        const raw = requireNext(args, ++i, arg);
        const colonIdx = raw.indexOf(':');
        if (colonIdx > 0) {
          result.headers.push([
            raw.substring(0, colonIdx).trim(),
            raw.substring(colonIdx + 1).trim(),
          ]);
        }
        break;
      }

      case '-d':
      case '--data':
      case '--data-ascii':
        result.data = requireNext(args, ++i, arg);
        if (result.method === 'GET') result.method = 'POST';
        break;

      case '--data-raw':
        result.dataRaw = requireNext(args, ++i, arg);
        if (result.method === 'GET') result.method = 'POST';
        break;

      case '-A':
      case '--user-agent':
        result.userAgent = requireNext(args, ++i, arg);
        break;

      // ---- Output ----
      case '-o':
      case '--output':
        result.output = requireNext(args, ++i, arg);
        break;

      case '-I':
      case '--head':
        result.head = true;
        result.method = 'HEAD';
        break;

      case '-i':
      case '--include':
        result.include = true;
        break;

      case '-v':
      case '--verbose':
        result.verbose = true;
        break;

      case '-s':
      case '--silent':
        result.silent = true;
        break;

      case '--compressed':
        result.compressed = true;
        break;

      // ---- Impersonation ----
      case '--impersonate':
        result.impersonate = requireNext(args, ++i, arg);
        break;

      case '--ja3':
        result.ja3 = requireNext(args, ++i, arg);
        break;

      case '--akamai':
        result.akamai = requireNext(args, ++i, arg);
        break;

      case '--stealth':
        result.stealth = true;
        break;

      case '--list-profiles':
        result.listProfiles = true;
        break;

      // ---- Connection ----
      case '-x':
      case '--proxy':
        result.proxy = requireNext(args, ++i, arg);
        break;

      case '-U':
      case '--proxy-user':
        result.proxyAuth = requireNext(args, ++i, arg);
        break;

      case '-k':
      case '--insecure':
        result.insecure = true;
        break;

      case '-L':
      case '--location':
        result.followRedirects = true;
        break;

      case '--no-location':
        result.followRedirects = false;
        break;

      case '--max-redirs':
        result.maxRedirects = parseInt(requireNext(args, ++i, arg), 10);
        break;

      case '-m':
      case '--max-time':
        result.timeout = Math.round(parseFloat(requireNext(args, ++i, arg)) * 1000);
        break;

      case '--http1.1':
        result.httpVersion = '1.1';
        break;

      case '--http2':
        result.httpVersion = '2';
        break;

      // ---- Cookies ----
      case '-b':
      case '--cookie':
        result.cookies = requireNext(args, ++i, arg);
        break;

      case '-c':
      case '--cookie-jar':
        result.cookieJar = requireNext(args, ++i, arg);
        break;

      // ---- Meta ----
      case '-h':
      case '--help':
        result.help = true;
        break;

      case '-V':
      case '--version':
        result.version = true;
        break;

      default:
        // Positional argument (URL)
        if (!arg.startsWith('-') && !result.url) {
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
    case '--impersonate': result.impersonate = value; break;
    case '--ja3': result.ja3 = value; break;
    case '--akamai': result.akamai = value; break;
    case '--proxy': result.proxy = value; break;
    case '--proxy-user': result.proxyAuth = value; break;
    case '--max-redirs': result.maxRedirects = parseInt(value, 10); break;
    case '--max-time': result.timeout = Math.round(parseFloat(value) * 1000); break;
    case '--output': result.output = value; break;
    case '--request': result.method = value.toUpperCase(); break;
    case '--user-agent': result.userAgent = value; break;
    case '--cookie': result.cookies = value; break;
    case '--cookie-jar': result.cookieJar = value; break;
    case '--header': {
      const colonIdx = value.indexOf(':');
      if (colonIdx > 0) {
        result.headers.push([
          value.substring(0, colonIdx).trim(),
          value.substring(colonIdx + 1).trim(),
        ]);
      }
      break;
    }
    case '--data':
    case '--data-ascii':
      result.data = value;
      if (result.method === 'GET') result.method = 'POST';
      break;
    case '--data-raw':
      result.dataRaw = value;
      if (result.method === 'GET') result.method = 'POST';
      break;
    default:
      break;
  }
}
