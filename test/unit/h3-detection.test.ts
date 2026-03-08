import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { isQuicAvailable, assertQuicAvailable, resetQuicDetection } from "../../src/http/h3/detection.js";
import { NLcURLError } from "../../src/core/errors.js";

describe("HTTP/3 Detection", () => {
  it("isQuicAvailable returns false on current Node.js", () => {
    resetQuicDetection();
    assert.equal(isQuicAvailable(), false);
  });

  it("assertQuicAvailable throws ERR_H3_UNAVAILABLE when QUIC not available", () => {
    resetQuicDetection();
    assert.throws(
      () => assertQuicAvailable(),
      (err: unknown) => {
        assert.ok(err instanceof NLcURLError);
        assert.equal((err as NLcURLError).code, "ERR_H3_UNAVAILABLE");
        return true;
      },
    );
  });

  it("resetQuicDetection clears cached state", () => {
    resetQuicDetection();
    assert.equal(isQuicAvailable(), false);
  });
});
