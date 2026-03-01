# Developer Onboarding Guide

This guide is for engineers contributing to NLcURL.

## 1. Repository Orientation

Primary areas:

- Public API and session flow: `src/index.ts`, `src/core/*`
- Protocol transport: `src/http/*`
- TLS engines: `src/tls/*`
- Fingerprint definitions: `src/fingerprints/*`
- CLI: `src/cli/*`
- Tests: `test/unit/*`, `test/integration/*`

Read these in order for fastest comprehension:

1. `README.md`
2. `docs/ARCHITECTURE.md`
3. `docs/API.md`
4. `src/core/session.ts`
5. `src/http/negotiator.ts`

## 2. Local Setup

```bash
npm install
npm run build
npm run lint
npm run test
```

Optional full validation:

```bash
npm run test:integration
```

## 3. Coding and Design Conventions

- TypeScript `strict` mode is enabled.
- Use ESM imports/exports.
- Keep runtime dependency footprint at zero.
- Prefer explicit types for public APIs.
- Add TSDoc for all exported types/classes/functions.
- Preserve deterministic behavior in protocol and fingerprint logic.

## 4. Testing Expectations

When changing core behavior:

- Add/adjust unit tests in `test/unit/`.
- Add integration coverage for request-level behavior changes in `test/integration/client/tests/`.
- Ensure failing-path errors are covered (timeouts, protocol errors, invalid inputs).

## 5. Contribution Checklist

1. Build succeeds (`npm run build`).
2. Type checks succeed (`npm run lint`).
3. Unit tests pass (`npm run test`).
4. Integration tests pass for behavior changes (`npm run test:integration`).
5. Documentation updated in `README.md` and relevant files under `docs/`.

## 6. Common Extension Points

- Add a browser profile:

1. Update corresponding `src/fingerprints/profiles/*.ts` file.
2. Include map entries and latest alias where appropriate.
3. Add/adjust unit tests for fingerprint expectations.

- Add request middleware behavior:

1. Extend modules in `src/middleware/`.
2. Wire integration in `src/core/session.ts`.
3. Add tests and docs.

- Add CLI options:

1. Update parser (`src/cli/args.ts`).
2. Update request mapping (`src/cli/index.ts`).
3. Update help output (`src/cli/output.ts`).
4. Update `README.md` and `docs/CONFIGURATION.md`.

## 7. Known Workstreams

Current repository already contains reusable modules that can be integrated into top-level flow:

- Proxy tunneling integration for `proxy` and `proxyAuth` request/session options.
- Retry integration for `retry` session config.
- CLI cookie-jar file persistence for `--cookie-jar`.

These are documented as scope notes in `README.md` and `docs/CONFIGURATION.md`.
