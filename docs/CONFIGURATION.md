# Environment and Configuration

NLcURL does not currently depend on environment variables for runtime behavior. Configuration is supplied through request/session objects and CLI flags.

## Runtime Configuration Surfaces

1. Programmatic request (`NLcURLRequest`)
2. Programmatic session (`NLcURLSessionConfig`)
3. CLI flags (`nlcurl [OPTIONS] <URL>`)

## Programmatic Request Configuration

Key fields:

- `url`, `method`, `headers`, `body`
- `timeout` (`number` or phase-specific `TimeoutConfig`)
- `signal` (`AbortSignal`)
- `impersonate`, `stealth`, `ja3`, `akamai`
- `followRedirects`, `maxRedirects`, `insecure`
- `httpVersion`, `baseURL`, `params`
- `cookieJar`, `acceptEncoding`, `headerOrder`
- `proxy`, `proxyAuth`
- `stream` — when `true`, response body is returned as a `Readable` stream; `text()` / `json()` throw
- `dnsFamily` — `4` or `6` to pin the Happy Eyeballs resolver to a single address family. When omitted, both A and AAAA records are resolved and raced per RFC 8305.

## Programmatic Session Configuration

Session defaults are merged into request-level values unless overridden.

Useful defaults for production client wrappers:

- `baseURL`
- `headers`
- `impersonate`
- `timeout`
- `followRedirects` / `maxRedirects`
- `cookieJar`
- `dnsFamily` — pin the Happy Eyeballs resolver to IPv4 (`4`) or IPv6 (`6`); omit to enable automatic dual-stack racing (RFC 8305)

## CLI Mapping

Representative mapping:

- `--request` -> `method`
- `--header` -> `headers`
- `--data` / `--data-raw` -> `body`
- `--impersonate` -> `impersonate`
- `--stealth` -> `stealth`
- `--ja3` -> `ja3`
- `--akamai` -> `akamai`
- `--proxy` -> `proxy`
- `--proxy-user` -> `proxyAuth`
- `--insecure` -> `insecure`
- `--no-location` / `--max-redirs` -> redirect controls
- `--max-time` -> `timeout` (seconds converted to ms)
- `--http1.1` / `--http2` -> `httpVersion`

## Defaults

Default values in parser/session include:

- method: `GET`
- timeout: `30000ms` (CLI default)
- follow redirects: `true`
- max redirects: `20`
- insecure TLS: `false`

## Body Serialization and Content-Type

When a `body` is provided without an explicit `Content-Type` header:

- **Plain object** (`Record<string, unknown>`): serialized with `JSON.stringify()`, Content-Type set to `application/json`.
- **String**: Content-Type defaults to `text/plain; charset=utf-8`.
- **URLSearchParams**: Content-Type defaults to `application/x-www-form-urlencoded`.
- **Buffer or stream**: no default Content-Type is set.

Provide an explicit `Content-Type` header to override this behavior.

## Redirect Behavior

Redirects follow RFC 7231 semantics:

- **301 / 302 + POST**: method changes to GET, body is cleared, `content-type` and `content-length` are stripped.
- **303**: method always changes to GET, body is cleared, content headers stripped.
- **307 / 308**: method and body are **preserved**; `content-type` and `content-length` are not stripped.
- `authorization` and `proxy-authorization` headers are stripped on cross-origin redirects regardless of status code.

## Request Timings

`NLcURLResponse.timings` fields (all in milliseconds, measured on the sending side):

- `dns`: time to resolve the hostname.
- `connect`: time to establish the TCP connection.
- `tls`: time to complete the TLS handshake.
- `firstByte`: time from sending the request to receiving the first response byte.
- `total`: total wall-clock duration.

## Operational Notes

- `proxy` / `proxyAuth`: the protocol negotiator tunnels through HTTP CONNECT or SOCKS4/5 proxies when `request.proxy` is set.
- `retry`: `NLcURLSession.request()` automatically invokes `withRetry()` when `retry.count > 0` in session config. Supports exponential/linear backoff, jitter, H2 error code retries (codes 1, 2, 7, 11), and custom predicates.
- `cookieJar`: when set on a per-request basis via the one-shot functions (`request()`, `get()`, etc.), the value is forwarded to the temporary session, so cookie capture and injection work on single requests too.
- CLI `--cookie-jar`: loads cookies from file before the request and saves them back in Netscape format after.

## Security Guidance

- Avoid `insecure: true` outside test environments.
- Treat header and cookie values as sensitive data.
- If using proxy auth, avoid logging credentials.

## Suggested Production Baseline

```ts
import { createSession } from "nlcurl";

const session = createSession({
  baseURL: "https://api.example.com",
  impersonate: "chrome136",
  timeout: { connect: 5000, response: 15000, total: 20000 },
  followRedirects: true,
  maxRedirects: 5,
  cookieJar: true,
});
```
