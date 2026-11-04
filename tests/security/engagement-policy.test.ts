import { describe, expect, it } from "vitest";
import {
  assertEngagementTransition,
  evaluateExecution,
  hasPermission,
  type ExecutionPolicyState,
} from "@aasp/security-core";

const now = new Date("2026-09-08T12:00:00Z");
const policy: ExecutionPolicyState = {
  state: "TESTING",
  currentRevision: 2,
  grantedRevision: 2,
  scopeMatches: true,
  revoked: false,
  grantStartsAt: new Date("2026-09-08T10:00:00Z"),
  grantExpiresAt: new Date("2026-09-08T14:00:00Z"),
  windowStartsAt: new Date("2026-09-08T11:00:00Z"),
  windowEndsAt: new Date("2026-09-08T13:00:00Z"),
  maxRisk: "LOW_IMPACT",
  allowedCategories: ["DISCOVERY", "AUTHORIZATION"],
  allowedProtocols: ["https:"],
  testerRole: "PENTESTER",
  testerActive: true,
  cancelled: false,
};
const action = { method: "GET", category: "AUTHORIZATION" as const, protocol: "https:" };

describe("engagement execution policy", () => {
  it("permits a scoped, authorized comparison with current permission", () => {
    expect(evaluateExecution(policy, action, now)).toEqual({
      permitted: true,
      code: "PERMITTED",
      risk: "LOW_IMPACT",
    });
  });
  it.each([
    [{ revoked: true }, "AUTHORIZATION_REVOKED"],
    [{ currentRevision: 3 }, "AUTHORIZATION_STALE"],
    [{ scopeMatches: false }, "AUTHORIZATION_STALE"],
    [{ testerRole: "CLIENT_ADMIN" }, "TESTER_PERMISSION_DENIED"],
    [{ testerRole: "PLATFORM_ADMIN" }, "TESTER_PERMISSION_DENIED"],
    [{ testerRole: "JUNIOR_PENTESTER" }, "TESTER_PERMISSION_DENIED"],
    [{ testerActive: false }, "TESTER_PERMISSION_DENIED"],
    [{ cancelled: true }, "EXECUTION_CANCELLED"],
    [{ state: "AUTHORIZED" }, "ENGAGEMENT_NOT_TESTING"],
    [{ grantExpiresAt: now }, "AUTHORIZATION_OUTSIDE_WINDOW"],
    [{ windowEndsAt: now }, "OUTSIDE_TESTING_WINDOW"],
    [{ windowStartsAt: new Date(NaN) }, "INVALID_TESTING_WINDOW"],
    [{ allowedCategories: ["DISCOVERY"] }, "TEST_CATEGORY_DENIED"],
    [{ allowedProtocols: ["http:"] }, "PROTOCOL_DENIED"],
    [{ maxRisk: "SAFE" }, "RISK_EXCEEDS_ROE"],
  ])("fails closed for %j", (change, code) => {
    expect(
      evaluateExecution({ ...policy, ...change } as ExecutionPolicyState, action, now),
    ).toMatchObject({ permitted: false, code });
  });
  it("does not let an administrator or AI approval flag activate an unsupported mutation", () => {
    const input = {
      ...policy,
      testerRole: "OWNER",
      maxRisk: "RESTRICTED" as const,
      approved: true,
      requiresApproval: false,
    };
    expect(evaluateExecution(input, { ...action, method: "DELETE" }, now)).toMatchObject({
      permitted: false,
      code: "SENSITIVE_CAPABILITY_NOT_ENABLED",
    });
  });
  it("enforces lifecycle order and least privilege", () => {
    expect(() => assertEngagementTransition("DRAFT", "TESTING")).toThrow();
    expect(() => assertEngagementTransition("ARCHIVED", "SCOPING")).toThrow();
    expect(() => assertEngagementTransition("TESTING", "INTERNAL_REVIEW")).not.toThrow();
    expect(hasPermission("ANALYST", "scope.modify")).toBe(false);
    expect(hasPermission("REVIEWER", "test.execute.safe")).toBe(false);
    expect(hasPermission("CLIENT_USER", "evidence.read")).toBe(false);
  });
});
