export const engagementStates = [
  "DRAFT",
  "SCOPING",
  "AWAITING_AUTHORIZATION",
  "AUTHORIZED",
  "SCHEDULED",
  "ACTIVE",
  "TESTING",
  "INTERNAL_REVIEW",
  "CLIENT_REVIEW",
  "REMEDIATION",
  "RETEST",
  "COMPLETED",
  "ARCHIVED",
] as const;
export type EngagementState = (typeof engagementStates)[number];

export const engagementTransitions: Readonly<Record<EngagementState, readonly EngagementState[]>> =
  {
    DRAFT: ["SCOPING", "ARCHIVED"],
    SCOPING: ["AWAITING_AUTHORIZATION", "ARCHIVED"],
    AWAITING_AUTHORIZATION: ["SCOPING", "AUTHORIZED", "ARCHIVED"],
    AUTHORIZED: ["SCOPING", "SCHEDULED"],
    SCHEDULED: ["SCOPING", "ACTIVE"],
    ACTIVE: ["TESTING", "SCOPING"],
    TESTING: ["INTERNAL_REVIEW", "SCOPING"],
    INTERNAL_REVIEW: ["TESTING", "CLIENT_REVIEW", "SCOPING"],
    CLIENT_REVIEW: ["INTERNAL_REVIEW", "REMEDIATION"],
    REMEDIATION: ["RETEST", "COMPLETED", "SCOPING"],
    RETEST: ["INTERNAL_REVIEW", "REMEDIATION", "COMPLETED", "SCOPING"],
    COMPLETED: ["ARCHIVED"],
    ARCHIVED: [],
  };

export function assertEngagementTransition(from: EngagementState, to: EngagementState): void {
  if (!engagementTransitions[from]?.includes(to))
    throw new Error(`Engagement cannot transition from ${from} to ${to}.`);
}

export const permissions = [
  "client.read",
  "client.create",
  "engagement.read",
  "engagement.create",
  "engagement.transition",
  "engagement.authorize",
  "scope.modify",
  "test.execute.safe",
  "test.execute.high_impact",
  "finding.create",
  "finding.review",
  "finding.approve",
  "finding.publish",
  "evidence.read",
  "evidence.read_sensitive",
  "report.generate",
  "report.publish",
  "integration.manage",
] as const;
export type Permission = (typeof permissions)[number];

const read: Permission[] = ["client.read", "engagement.read"];
const test: Permission[] = [...read, "test.execute.safe", "finding.create", "evidence.read"];
const management: Permission[] = [
  ...test,
  "client.create",
  "engagement.create",
  "engagement.transition",
  "scope.modify",
  "finding.review",
  "report.generate",
];
const roles: Readonly<Record<string, readonly Permission[]>> = {
  OWNER: permissions,
  ADMIN: permissions,
  ORG_OWNER: permissions,
  SECURITY_DIRECTOR: permissions,
  PENTEST_MANAGER: management,
  LEAD_PENTESTER: [...management, "finding.approve"],
  ANALYST: test,
  PENTESTER: test,
  JUNIOR_PENTESTER: read,
  REVIEWER: [...read, "evidence.read", "finding.review", "finding.approve"],
  VIEWER: read,
  // Platform administration and client membership confer no internal tenant access.
  PLATFORM_ADMIN: [],
  CLIENT_ADMIN: [],
  CLIENT_USER: [],
};

export function hasPermission(role: string, permission: Permission): boolean {
  return roles[role]?.includes(permission) ?? false;
}

export const actionRisks = [
  "PASSIVE",
  "SAFE",
  "LOW_IMPACT",
  "MODERATE_IMPACT",
  "HIGH_IMPACT",
  "RESTRICTED",
] as const;
export type ActionRisk = (typeof actionRisks)[number];
export type TestCategory = "DISCOVERY" | "HTTP_CONFIGURATION" | "AUTHORIZATION";

export interface ExecutionPolicyState {
  state: EngagementState;
  currentRevision: number;
  grantedRevision: number;
  scopeMatches: boolean;
  revoked: boolean;
  grantStartsAt: Date;
  grantExpiresAt: Date;
  windowStartsAt: Date;
  windowEndsAt: Date;
  maxRisk: ActionRisk;
  allowedCategories: readonly string[];
  allowedProtocols: readonly string[];
  testerRole: string;
  testerActive: boolean;
  cancelled: boolean;
}

export type ExecutionDecision = { permitted: boolean; code: string; risk: ActionRisk };

/** Risk comes from our adapter catalog and actual HTTP method, never request/model JSON. */
export function evaluateExecution(
  policy: ExecutionPolicyState,
  action: { method: string; category: TestCategory; protocol: string },
  now: Date,
): ExecutionDecision {
  const safeMethod = ["GET", "HEAD", "OPTIONS"].includes(action.method);
  const risk: ActionRisk = safeMethod
    ? action.category === "AUTHORIZATION"
      ? "LOW_IMPACT"
      : "SAFE"
    : "HIGH_IMPACT";
  const deny = (code: string): ExecutionDecision => ({ permitted: false, code, risk });
  if (!policy.testerActive || !hasPermission(policy.testerRole, "test.execute.safe"))
    return deny("TESTER_PERMISSION_DENIED");
  if (policy.cancelled) return deny("EXECUTION_CANCELLED");
  if (!["TESTING", "RETEST"].includes(policy.state)) return deny("ENGAGEMENT_NOT_TESTING");
  if (policy.revoked) return deny("AUTHORIZATION_REVOKED");
  if (policy.currentRevision !== policy.grantedRevision || !policy.scopeMatches)
    return deny("AUTHORIZATION_STALE");
  const instant = now.getTime();
  if (
    ![
      policy.grantStartsAt,
      policy.grantExpiresAt,
      policy.windowStartsAt,
      policy.windowEndsAt,
      now,
    ].every((d) => Number.isFinite(d.getTime()))
  )
    return deny("INVALID_TESTING_WINDOW");
  if (instant < policy.grantStartsAt.getTime() || instant >= policy.grantExpiresAt.getTime())
    return deny("AUTHORIZATION_OUTSIDE_WINDOW");
  if (instant < policy.windowStartsAt.getTime() || instant >= policy.windowEndsAt.getTime())
    return deny("OUTSIDE_TESTING_WINDOW");
  if (!policy.allowedProtocols.includes(action.protocol)) return deny("PROTOCOL_DENIED");
  if (!policy.allowedCategories.includes(action.category)) return deny("TEST_CATEGORY_DENIED");
  if (!safeMethod) return deny("SENSITIVE_CAPABILITY_NOT_ENABLED");
  if (actionRisks.indexOf(risk) > actionRisks.indexOf(policy.maxRisk))
    return deny("RISK_EXCEEDS_ROE");
  return { permitted: true, code: "PERMITTED", risk };
}
