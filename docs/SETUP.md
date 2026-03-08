# Setup Guide

Build, test, and development environment instructions for NLcURL.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Building](#building)
- [Testing](#testing)
- [Formatting and Linting](#formatting-and-linting)
- [Project Structure](#project-structure)
- [TypeScript Configuration](#typescript-configuration)
- [Publishing](#publishing)
- [Maintenance Scripts](#maintenance-scripts)

---

## Prerequisites

| Requirement | Version | Purpose |
|---|---|---|
| Node.js | >= 18.17.0 | Runtime |
| npm | >= 9.0.0 | Package management (ships with Node.js) |

No native compiler, Python, or system libraries are required. NLcURL has zero runtime dependencies.

Verify your environment:

```bash
node --version
# v18.17.0 or higher

npm --version
# 9.0.0 or higher
```

---

## Installation

Clone the repository and install development dependencies:

```bash
git clone <repository-url>
cd NLcURL
npm install
```

**Dev dependencies installed:**

| Package | Version | Purpose |
|---|---|---|
| `typescript` | ^5.9.3 | TypeScript compiler |
| `tsx` | ^4.21.0 | TypeScript execution for tests and scripts |
| `prettier` | ^3.8.1 | Code formatting |
| `@types/node` | ^25.3.5 | Node.js type definitions |

---

## Building

Compile TypeScript source to JavaScript:

```bash
npm run build
```

This runs `tsc` and outputs compiled files to `dist/`:

```
dist/
  index.js          # Main entry point
  index.d.ts        # Type declarations
  index.js.map      # Source maps
  cli/
  core/
  http/
  tls/
  ...
```

**Clean build output:**

```bash
npm run clean
```

Removes the `dist/` directory entirely.

**Type checking without emitting:**

```bash
npm run lint
```

Runs `tsc --noEmit` to report type errors without producing output files.

---

## Testing

NLcURL uses the Node.js built-in test runner with `tsx` for TypeScript support.

### Unit Tests

```bash
npm test
```

Runs: `node --import tsx --test test/unit/**/*.test.ts`

Unit tests cover all modules: TLS fingerprinting, cookie parsing, DNS codec, HTTP/1.1 parser, HTTP/2 HPACK, cache logic, encoding, proxy resolution, error handling, and more.

### Integration Tests

```bash
npm run test:integration
```

Runs: `node --import tsx --test test/integration/**/*.test.ts`

Integration tests exercise full request flows against local test servers.

### All Tests

```bash
npm run test:all
```

Runs: `node --import tsx --test test/**/*.test.ts`

Executes both unit and integration test suites.

### Running a Specific Test File

```bash
node --import tsx --test test/unit/cookies.test.ts
```

### Test Structure

```
test/
  unit/                     # Unit tests (no network)
    cookies.test.ts
    dns-codec.test.ts
    h1-encoder.test.ts
    h1-parser.test.ts
    h2-frames.test.ts
    hpack.test.ts
    cache.test.ts
    ...
  integration/              # End-to-end tests
    client/                 # Client-side test suites
    server/                 # Local test server fixtures
```

---

## Formatting and Linting

### Format Code

```bash
npm run format
```

Runs Prettier across the entire project.

### Check Formatting

```bash
npm run format:check
```

Runs Prettier in check mode — reports unformatted files without modifying them. Useful in CI.

### Type Checking

```bash
npm run lint
```

Runs the TypeScript compiler with `--noEmit` to detect type errors without generating output.

---

## Project Structure

```
NLcURL/
├── package.json            # Project metadata, scripts, dependencies
├── tsconfig.json           # TypeScript compiler configuration
├── LICENSE                 # MIT license
├── README.md               # Project overview
├── docs/                   # Documentation
│   ├── API.md              # Complete API reference
│   ├── CONFIGURATION.md    # All configuration options
│   ├── EXAMPLES.md         # Usage examples
│   ├── MODULES.md          # Internal module architecture
│   ├── ONBOARDING.md       # Getting started guide
│   └── SETUP.md            # This file
├── scripts/
│   └── update-psl.ts       # Public Suffix List updater
├── src/                    # Source code
│   ├── index.ts            # Main entry point (re-exports)
│   ├── core/               # Public API, session, request/response types, errors
│   ├── http/               # Protocol negotiation, connection pooling
│   │   ├── h1/             # HTTP/1.1 client, encoder, parser
│   │   ├── h2/             # HTTP/2 client, frames, HPACK
│   │   └── h3/             # HTTP/3 detection (no transport)
│   ├── tls/                # TLS configuration, certificate verification
│   │   └── stealth/        # Custom TLS 1.2/1.3 engine
│   ├── fingerprints/       # Browser profile database, JA3/JA4/Akamai
│   │   └── profiles/       # Individual browser profile data
│   ├── cookies/            # Cookie jar, parser, public suffix list
│   ├── cache/              # HTTP response cache, range cache
│   ├── hsts/               # HSTS policy store
│   ├── dns/                # DoH, DoT, HTTPS RR, DNS cache
│   ├── proxy/              # HTTP CONNECT, SOCKS4/5, proxy auth
│   ├── ws/                 # WebSocket client
│   ├── sse/                # Server-Sent Events parser
│   ├── middleware/          # Interceptors, retry, rate limiter
│   ├── utils/              # Compression, encoding, logging, buffers
│   └── cli/                # CLI entry point, argument parser, output
└── test/                   # Test suites
    ├── unit/               # Unit tests
    └── integration/        # Integration tests
```

---

## TypeScript Configuration

The project uses strict TypeScript with the following compiler options:

| Option | Value | Purpose |
|---|---|---|
| `target` | ES2022 | Output ECMAScript version |
| `module` | Node16 | ESM with Node.js module resolution |
| `moduleResolution` | Node16 | Node.js ESM resolution algorithm |
| `lib` | ES2022 | Standard library types |
| `outDir` | ./dist | Compiled output directory |
| `rootDir` | ./src | Source root |
| `declaration` | true | Generate .d.ts type declaration files |
| `declarationMap` | true | Generate declaration source maps |
| `sourceMap` | true | Generate .js.map source maps |
| `strict` | true | All strict type-checking options |
| `noUncheckedIndexedAccess` | true | Add undefined to index signatures |
| `noImplicitOverride` | true | Require override keyword |
| `noPropertyAccessFromIndexSignature` | true | Require bracket notation for index signatures |
| `forceConsistentCasingInFileNames` | true | Enforce consistent file name casing |
| `esModuleInterop` | true | CommonJS/ESM interop helpers |
| `isolatedModules` | true | Ensure each file can be independently transpiled |
| `newLine` | lf | Enforce Unix line endings |

The package is configured as ESM (`"type": "module"` in package.json).

---

## Publishing

The `prepublishOnly` script runs automatically before `npm publish`:

```bash
npm run prepublishOnly
# Equivalent to: npm run clean && npm run build && npm run test
```

This ensures the package is built from a clean state and all tests pass before publishing.

**Published files** (defined in `package.json` `files` field):

- `dist/` — compiled JavaScript, type declarations, and source maps
- `LICENSE` — MIT license
- `README.md` — project overview

Source code, tests, docs, and dev configuration are excluded from the published package.

**Entry points:**

| Field | Value | Purpose |
|---|---|---|
| `main` | ./dist/index.js | CommonJS/default entry point |
| `types` | ./dist/index.d.ts | TypeScript type declarations |
| `exports["."].import` | ./dist/index.js | ESM import entry point |
| `exports["."].types` | ./dist/index.d.ts | TypeScript types for ESM |
| `bin.nlcurl` | ./dist/cli/index.js | CLI executable |

---

## Maintenance Scripts

### Update Public Suffix List

```bash
npm run update-psl
```

Runs `tsx scripts/update-psl.ts` to fetch the latest Mozilla Public Suffix List and regenerate `src/cookies/psl-data.ts`. Run this periodically to keep cookie domain scoping accurate.