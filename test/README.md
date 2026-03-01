# Testing Guide

## Test Layout

- Unit tests: `test/unit/*.test.ts`
- Integration tests: `test/integration/client/tests/*.ts`
- Integration server: `test/integration/server/server.js`

## Running Tests

From repository root:

```bash
npm run test
npm run test:integration
npm run test:all
```

## Integration Test Flow

1. Runner starts HTTPS server (`test/integration/server/server.js`).
2. Runner executes grouped suites from `test/integration/client/tests/`.
3. Runner reports pass/fail summary and terminates server.

## Coverage Areas

Integration suites validate:

- HTTP methods and payloads
- headers and status codes
- cookies and redirects
- query params
- middleware behavior
- timeout and abort handling
- compression and chunked responses
- response model consistency

## Debugging a Failing Integration Suite

1. Run a single suite by editing `test/integration/client/runner.ts` suite list.
2. Observe server stderr output prefixed as `[server]`.
3. Reproduce request path using CLI (`node dist/cli/index.js ...`) or session API.
