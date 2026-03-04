import { describe, it, mock } from "node:test";
import assert from "node:assert/strict";

describe("Fix 9 – AbortSignal listener cleanup pattern", () => {
  it("removeEventListener is callable after addEventListener", () => {
    const ac = new AbortController();

    let listenerCalled = false;
    const onAbort = () => {
      listenerCalled = true;
    };

    ac.signal.addEventListener("abort", onAbort, { once: true });
    ac.signal.removeEventListener("abort", onAbort);

    ac.abort();

    assert.equal(listenerCalled, false, "Listener should not fire after removal");
  });

  it("AbortSignal listener fires if NOT removed", () => {
    const ac = new AbortController();

    let listenerCalled = false;
    const onAbort = () => {
      listenerCalled = true;
    };

    ac.signal.addEventListener("abort", onAbort, { once: true });

    ac.abort();
    assert.equal(listenerCalled, true, "Listener should fire when not removed");
  });

  it("removing an already-fired once listener is safe", () => {
    const ac = new AbortController();

    const onAbort = () => {};
    ac.signal.addEventListener("abort", onAbort, { once: true });
    ac.abort();

    assert.doesNotThrow(() => {
      ac.signal.removeEventListener("abort", onAbort);
    });
  });
});
