import { describe, expect, it } from "vitest";
import { assertTargetReadyForScan, TargetReadinessError } from "@aasp/security-core";

describe("target readiness invariant", () => {
  it.each(["DRAFT", "SCANNING", "DISABLED"] as const)(
    "prevents a %s target from starting an assessment",
    (status) => {
      expect(() => assertTargetReadyForScan({ status })).toThrowError(TargetReadinessError);
    },
  );

  it.each(["READY", "COMPLETED", "FAILED", "CANCELLED"] as const)(
    "allows an enabled, scope-configured %s target",
    (status) => {
      expect(() => assertTargetReadyForScan({ status })).not.toThrow();
    },
  );
});
