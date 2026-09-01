import { describe, expect, it } from "vitest";
import { assertCurrentTargetAuthorization, TargetAuthorizationError } from "@aasp/security-core";

describe("target authorization invariant", () => {
  const future = new Date("2030-01-01T00:00:00.000Z");
  const now = new Date("2029-01-01T00:00:00.000Z");

  it.each(["PENDING_VERIFICATION", "REJECTED", "DISABLED"] as const)(
    "prevents a %s target from starting an assessment",
    (status) => {
      expect(() =>
        assertCurrentTargetAuthorization({ status, authorizationExpiresAt: future }, now),
      ).toThrowError(TargetAuthorizationError);
    },
  );

  it("prevents an expired authorization from starting an assessment", () => {
    expect(() =>
      assertCurrentTargetAuthorization(
        { status: "VERIFIED", authorizationExpiresAt: new Date("2028-01-01T00:00:00.000Z") },
        now,
      ),
    ).toThrowError(TargetAuthorizationError);
  });

  it("allows only a currently verified target", () => {
    expect(() =>
      assertCurrentTargetAuthorization({ status: "VERIFIED", authorizationExpiresAt: future }, now),
    ).not.toThrow();
  });
});
