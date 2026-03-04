import { fork, type ChildProcess } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SERVER_SCRIPT = path.resolve(__dirname, "..", "server", "server.js");

interface TestResult {
  name: string;
  passed: boolean;
  error?: string;
  duration: number;
}

const results: TestResult[] = [];
let baseURL = "";

export function getBaseURL(): string {
  return baseURL;
}

export async function test(name: string, fn: () => Promise<void>): Promise<void> {
  const start = Date.now();
  try {
    await fn();
    results.push({ name, passed: true, duration: Date.now() - start });
    process.stdout.write(`  [OK] ${name} (${Date.now() - start}ms)\n`);
  } catch (err: any) {
    const msg = err?.message ?? String(err);
    results.push({ name, passed: false, error: msg, duration: Date.now() - start });
    process.stdout.write(`  [FAIL] ${name} (${Date.now() - start}ms)\n    → ${msg}\n`);
  }
}

export function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(`Assertion failed: ${message}`);
}

export function assertEqual(actual: unknown, expected: unknown, label = ""): void {
  if (actual !== expected) {
    throw new Error(`${label ? label + ": " : ""}expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}

export function assertIncludes(str: string, sub: string, label = ""): void {
  if (!str.includes(sub)) {
    throw new Error(`${label ? label + ": " : ""}expected "${str}" to include "${sub}"`);
  }
}

export function assertDeepEqual(actual: unknown, expected: unknown, label = ""): void {
  const a = JSON.stringify(actual);
  const b = JSON.stringify(expected);
  if (a !== b) {
    throw new Error(`${label ? label + ": " : ""}expected ${b}, got ${a}`);
  }
}

function startServer(): Promise<{ process: ChildProcess; port: number }> {
  return new Promise((resolve, reject) => {
    const child = fork(SERVER_SCRIPT, [], {
      stdio: ["pipe", "pipe", "pipe", "ipc"],
    });

    let output = "";
    child.stdout!.on("data", (chunk: Buffer) => {
      output += chunk.toString();
      const match = output.match(/NLCURL_TEST_PORT=(\d+)/);
      if (match) {
        resolve({ process: child, port: parseInt(match[1], 10) });
      }
    });

    child.stderr!.on("data", (chunk: Buffer) => {
      process.stderr.write(`[server] ${chunk}`);
    });

    child.on("error", reject);

    child.on("exit", (code) => {
      if (code !== 0) reject(new Error(`Server exited with code ${code}`));
    });

    setTimeout(() => reject(new Error("Server startup timed out")), 10000);
  });
}

async function main() {
  console.log("━━━ NLcURL Integration Tests ━━━\n");
  console.log("Starting test server...");

  const serverInfo = await startServer();
  baseURL = `https://127.0.0.1:${serverInfo.port}`;
  console.log(`Server running at ${baseURL}\n`);

  try {
    const suites = [
      ["Basic HTTP Methods", () => import("./tests/methods.js")],
      ["JSON & Body Handling", () => import("./tests/body.js")],
      ["Headers", () => import("./tests/headers.js")],
      ["Status Codes", () => import("./tests/status.js")],
      ["Cookies", () => import("./tests/cookies.js")],
      ["Redirects", () => import("./tests/redirects.js")],
      ["Session & Configuration", () => import("./tests/session.js")],
      ["Query Parameters", () => import("./tests/params.js")],
      ["Middleware & Interceptors", () => import("./tests/middleware.js")],
      ["Timeouts & Abort", () => import("./tests/timeouts.js")],
      ["Response Properties", () => import("./tests/response.js")],
      ["Error Handling", () => import("./tests/errors.js")],
      ["Compression", () => import("./tests/compression.js")],
      ["Large Payloads & Chunked", () => import("./tests/streaming.js")],
    ] as const;

    for (const [suiteName, loader] of suites) {
      console.log(`\n ${suiteName}`);
      try {
        const mod = await loader();
        await mod.default();
      } catch (err: any) {
        console.error(`  [FAIL] Suite failed to load: ${err.message}`);
        results.push({ name: `[${suiteName}] SUITE LOAD FAILURE`, passed: false, error: err.message, duration: 0 });
      }
    }
  } finally {
    serverInfo.process.kill("SIGTERM");
    setTimeout(() => serverInfo.process.kill("SIGKILL"), 2000);
  }

  console.log("\n━━━ Results ━━━");
  const passed = results.filter((r) => r.passed).length;
  const failed = results.filter((r) => !r.passed).length;
  const total = results.length;
  const totalDuration = results.reduce((s, r) => s + r.duration, 0);

  console.log(`\n  Total:  ${total}`);
  console.log(`  Passed: ${passed}`);
  console.log(`  Failed: ${failed}`);
  console.log(`  Time:   ${totalDuration}ms`);

  if (failed > 0) {
    console.log("\n  Failed tests:");
    for (const r of results.filter((r) => !r.passed)) {
      console.log(`    [FAIL] ${r.name}`);
      console.log(`      ${r.error}`);
    }
    process.exit(1);
  } else {
    console.log("\n  All tests passed! [OK]");
    process.exit(0);
  }
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(2);
});
