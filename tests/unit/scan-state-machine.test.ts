import { describe, expect, it } from "vitest";
import { assertScanTransition, InvalidScanTransitionError } from "@aasp/security-core";

describe("scan state machine", () => {
  it("accepts an immediate created-to-queued start transition", () => {
    expect(() => assertScanTransition("CREATED", "QUEUED")).not.toThrow();
  });

  it("rejects skipping queueing and discovery", () => {
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
