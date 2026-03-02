# NLcURL

Pure TypeScript HTTP client with browser fingerprint impersonation.

NLcURL provides session-based and one-shot HTTP APIs, browser profile impersonation, HTTP/2 support, cookie management, and a CLI. The project has zero runtime dependencies and uses only Node.js built-in modules.

## Highlights

- Zero runtime dependencies
- Session API with connection pooling
- HTTP/1.1 and HTTP/2 (ALPN negotiated) with RFC 9113 flow control
- Browser profile impersonation (Chrome, Firefox, Safari, Edge, Tor)
- Optional custom JA3 and Akamai H2 fingerprint values in request model
- Cookie jar with RFC 6265-like behavior; `Set-Cookie` headers preserved individually via `getAll()`
- Streaming response support (`stream: true`) with automatic decompression
- Configurable DNS family (`dnsFamily: 4 | 6`) for IPv4/IPv6 control
- Automatic retry on H2 RST_STREAM protocol errors (codes 1, 2, 7, 11)
- CLI (`nlcurl`) for scripted and interactive use
- WebSocket client with optional impersonated TLS handshake

## Requirements

- Node.js `>= 18.17.0`
- npm (or compatible package manager)

## Installation

```bash
npm install nlcurl
```

For local development:

```bash
npm install
npm run build
```

## Quick Start

### One-shot request

```ts
import { request } from "nlcurl";

const response = await request({
  url: "https://httpbin.org/get",
  impersonate: "chrome136",
});

console.log(response.status);
console.log(response.json());
```

### Session-based usage

```ts
import { createSession } from "nlcurl";

const session = createSession({
  baseURL: "https://httpbin.org",
  impersonate: "firefox138",
  followRedirects: true,
});

const res = await session.get("/headers");
console.log(res.json());

session.close();
```

### CLI usage

```bash
nlcurl --impersonate chrome136 https://tls.browserleaks.com/json
```

## CLI Reference

```text
nlcurl [OPTIONS] <URL>
```

Key options:

- `-X, --request <METHOD>` HTTP method
- `-H, --header <Name: Value>` add request header
- `-d, --data <DATA>` request body
- `--data-raw <DATA>` raw request body
- `-A, --user-agent <AGENT>` custom User-Agent
- `-o, --output <FILE>` write response body to file
- `-I, --head` send HEAD request
- `-i, --include` include response headers
- `-v, --verbose` verbose request/response output
- `-s, --silent` suppress error output
- `--compressed` request compressed response
- `--impersonate <PROFILE>` browser profile
- `--stealth` use stealth TLS engine
- `--ja3 <FINGERPRINT>` custom JA3 fingerprint string
- `--akamai <FINGERPRINT>` custom Akamai HTTP/2 fingerprint string
- `--list-profiles` list available profiles
- `-x, --proxy <URL>` proxy URL (request model supports it)
- `-U, --proxy-user <USER:PASS>` proxy auth pair
- `-k, --insecure` disable TLS verification
- `-L, --location` follow redirects (default behavior)
- `--no-location` disable redirect following
- `--max-redirs <NUM>` max redirects (default `20`)
- `-m, --max-time <SECONDS>` total timeout
- `--http1.1` force HTTP/1.1
- `--http2` force HTTP/2
- `-b, --cookie <DATA>` send cookie header
- `-c, --cookie-jar <FILE>` capture cookie jar target file
- `-h, --help` show help
- `-V, --version` show version

For examples, see `docs/SETUP.md` and `docs/API.md`.

## Supported Browser Families

- Chrome (`chrome99` through `chrome136`, plus `chrome_latest` and `chrome` alias)
- Firefox (`firefox133` through `firefox138`, plus `firefox_latest` and `firefox` alias)
- Safari (`safari153` through `safari182`, plus `safari_latest` and `safari` alias)
- Edge (`edge99`, `edge101`, `edge126`, `edge131`, `edge136`, `edge_latest`, `edge` alias)
- Tor (`tor133`, `tor140`, `tor145`, `tor_latest`, `tor` alias)

Run `nlcurl --list-profiles` to view the exact runtime list.

## Development

```bash
npm install
npm run lint
npm run test
npm run test:integration
npm run build
```

Additional commands:

- `npm run clean` remove `dist`
- `npm run test:all` run all tests

## Documentation Index

- `docs/API.md`: exported API reference
- `docs/MODULES.md`: module-by-module usage guide
- `docs/ARCHITECTURE.md`: system architecture and request flow
- `docs/SETUP.md`: setup, build, and test instructions
- `docs/CONFIGURATION.md`: request/session/CLI configuration
- `docs/ONBOARDING.md`: contributor onboarding guide

## License

MIT. See `LICENSE`.
