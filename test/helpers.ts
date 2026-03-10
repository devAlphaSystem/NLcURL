/**
 * Shared test helpers for NLcURL test suite.
 * Provides assertion utilities and test data factories for Node.js built-in test runner.
 */
import { strict as assert } from "node:assert";

/**
 * Assert that a function throws an error with a specific type and matching message.
 */
export function assertThrows<T extends Error>(fn: () => unknown, errorType: new (...args: any[]) => T, messagePattern?: string | RegExp): T {
  try {
    fn();
    assert.fail(`Expected ${errorType.name} to be thrown, but no error was thrown`);
  } catch (err) {
    if (err instanceof assert.AssertionError) throw err;
    assert.ok(err instanceof errorType, `Expected ${errorType.name} but got ${(err as Error).constructor.name}: ${(err as Error).message}`);
    if (messagePattern) {
      if (typeof messagePattern === "string") {
        assert.ok((err as Error).message.includes(messagePattern), `Error message "${(err as Error).message}" does not include "${messagePattern}"`);
      } else {
        assert.ok(messagePattern.test((err as Error).message), `Error message "${(err as Error).message}" does not match ${messagePattern}`);
      }
    }
    return err as T;
  }
  throw new Error("Unreachable");
}

/**
 * Assert that an async function throws an error with a specific type and matching message.
 */
export async function assertThrowsAsync<T extends Error>(fn: () => Promise<unknown>, errorType: new (...args: any[]) => T, messagePattern?: string | RegExp): Promise<T> {
  try {
    await fn();
    assert.fail(`Expected ${errorType.name} to be thrown, but no error was thrown`);
  } catch (err) {
    if (err instanceof assert.AssertionError) throw err;
    assert.ok(err instanceof errorType, `Expected ${errorType.name} but got ${(err as Error).constructor.name}: ${(err as Error).message}`);
    if (messagePattern) {
      if (typeof messagePattern === "string") {
        assert.ok((err as Error).message.includes(messagePattern), `Error message "${(err as Error).message}" does not include "${messagePattern}"`);
      } else {
        assert.ok(messagePattern.test((err as Error).message), `Error message "${(err as Error).message}" does not match ${messagePattern}`);
      }
    }
    return err as T;
  }
  throw new Error("Unreachable");
}

/** Create a Buffer from a hex string. */
export function hexBuf(hex: string): Buffer {
  return Buffer.from(hex.replace(/\s/g, ""), "hex");
}

/** Create a Buffer from a UTF-8 string. */
export function utf8Buf(str: string): Buffer {
  return Buffer.from(str, "utf-8");
}
