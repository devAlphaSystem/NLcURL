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
- `dnsFamily` — `4` or `6` to restrict the OS resolver to IPv4-only or IPv6-only sockets

## Programmatic Session Configuration

Session defaults are merged into request-level values unless overridden.

Useful defaults for production client wrappers:

- `baseURL`
- `headers`
- `impersonate`
- `timeout`
- `followRedirects` / `maxRedirects`
- `cookieJar`
- `dnsFamily` — force IPv4 (`4`) or IPv6 (`6`) at the socket level

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

## Operational Notes

- `proxy` / `proxyAuth`: the protocol negotiator tunnels through HTTP CONNECT or SOCKS4/5 proxies when `request.proxy` is set.
- `retry`: `NLcURLSession.request()` automatically invokes `withRetry()` when `retry.count > 0` in session config. Supports exponential/linear backoff, jitter, H2 error code retries (codes 1, 2, 7, 11), and custom predicates.
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
