import { describe, expect, it } from "vitest";
import { assertScanTransition, InvalidScanTransitionError } from "@aasp/security-core";

describe("scan state machine", () => {
  it("accepts the persisted authorized-to-queued transition", () => {
    expect(() => assertScanTransition("AUTHORIZED", "QUEUED")).not.toThrow();
  });

  it("rejects skipping authorization and discovery", () => {
    expect(() => assertScanTransition("CREATED", "CRAWLING")).toThrowError(
      InvalidScanTransitionError,
    );
  });

  it("does not permit a completed scan to restart", () => {
    expect(() => assertScanTransition("COMPLETED", "QUEUED")).toThrowError(
      InvalidScanTransitionError,
    );
  });
});
