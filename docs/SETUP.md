# Setup and Installation

## Prerequisites

- Node.js `>= 18.17.0`
- npm `>= 9` recommended

## Local Development Setup

```bash
npm install
npm run build
```

Build artifacts are generated in `dist/`.

## Validate Build and Types

```bash
npm run lint
```

This runs TypeScript with `--noEmit`.

## Run Tests

### Unit tests

```bash
npm run test
```

### Integration tests

```bash
npm run test:integration
```

### All tests

```bash
npm run test:all
```

## Integration Test Components

- Client runner: `test/integration/client/runner.ts`
- Test suites: `test/integration/client/tests/*`
- HTTPS server: `test/integration/server/server.js`

The runner starts the server as a child process, executes suites, and stops the server.

## CLI Build and Use

After build:

```bash
node dist/cli/index.js --help
```

If installed globally or linked:

```bash
nlcurl --help
```

## Publish Pipeline

`prepublishOnly` script runs:

1. `npm run clean`
2. `npm run build`
3. `npm run test`

## Clean Artifacts

```bash
npm run clean
```

## Windows Notes

PowerShell examples:

```powershell
npm install
npm run build
npm run test
```

No additional native dependencies are required.
