import { createHash } from "node:crypto";
import type { PrismaClient } from "@aasp/database";
import {
  evaluateExecution,
  type ExecutionDecision as PolicyDecision,
  type TestCategory,
} from "@aasp/security-core";
import {
  assertDestinationAllowed,
  scopePolicyFromTarget,
  type PersistedTargetScope,
} from "@aasp/scope-engine";
import {
  audit,
  GovernanceError,
  lockEngagement,
  type DatabaseTransaction,
  type TenantActor,
} from "./context.js";

export function scopeDigest(target: PersistedTargetScope): string {
  const scope = scopePolicyFromTarget(target);
  return createHash("sha256")
    .update(
      JSON.stringify({
        origin: scope.targetOrigin,
        domains: [...(scope.allowedDomains ?? [])].sort(),
        ports: [...(scope.allowedPorts ?? [])].sort((a, b) => a - b),
        exclusions: [...(scope.excludedPathPrefixes ?? [])].sort(),
        includeSubdomains: scope.includeSubdomains,
        allowPrivateNetwork: scope.allowPrivateNetwork,
      }),
    )
    .digest("hex");
}

const tools: Readonly<Record<TestCategory, string>> = {
  DISCOVERY: "http-discovery@1",
  HTTP_CONFIGURATION: "http-configuration@1",
  AUTHORIZATION: "authorization-comparison@1",
};

async function evaluate(
  tx: DatabaseTransaction,
  ctx: TenantActor,
  scanId: string,
  action: { url: URL; method: string; category: TestCategory; phase: "QUEUE" | "TRANSPORT" },
  consume: boolean,
): Promise<{ decision: PolicyDecision; grantId?: string; waitMs?: number }> {
  const initial = await tx.scan.findFirst({
    where: { id: scanId, workspaceId: ctx.workspaceId },
    select: { engagementId: true },
  });
  const denied = (code: string): PolicyDecision => ({ permitted: false, code, risk: "RESTRICTED" });
  if (!initial?.engagementId) {
    await audit(tx, ctx, "execution.denied", "Scan", scanId, {
      code: "ENGAGEMENT_REQUIRED",
      phase: action.phase,
    });
    return { decision: denied("ENGAGEMENT_REQUIRED") };
  }
  const engagement = await lockEngagement(tx, ctx, initial.engagementId);
  const scan = await tx.scan.findFirstOrThrow({
    where: { id: scanId, workspaceId: ctx.workspaceId, engagementId: engagement.id },
    include: { config: true, target: { include: { scopeRules: { where: { enabled: true } } } } },
  });
  const [clock] = await tx.$queryRaw<Array<{ now: Date }>>`SELECT clock_timestamp() AS now`;
  if (!clock) throw new GovernanceError(503, "POLICY_CLOCK_UNAVAILABLE");
  const instant = clock.now;
  const member = await tx.workspaceMember.findFirst({
    where: {
      workspaceId: ctx.workspaceId,
      userId: ctx.userId,
      user: { isActive: true },
      workspace: { organization: { members: { some: { userId: ctx.userId } } } },
    },
    include: { role: true },
  });
  const grant = await tx.authorizationGrant.findFirst({
    where: {
      workspaceId: ctx.workspaceId,
      engagementId: engagement.id,
      ...(action.phase === "TRANSPORT"
        ? { id: scan.authorizationGrantId ?? "" }
        : {
            policyRevision: engagement.policyRevision,
            revocation: null,
            validFrom: { lte: instant },
            validUntil: { gt: instant },
          }),
    },
    include: { revocation: true, policy: { include: { targets: true } } },
    orderBy: { createdAt: "desc" },
  });
  const policy = grant?.policy;
  const target = policy?.targets.find((t) => t.targetId === scan.targetId);
  let matchingScope = false;
  try {
    matchingScope =
      !!target &&
      target.scopeRevision === scan.target.scopeRevision &&
      target.scopeDigest === scopeDigest(scan.target);
  } catch {
    matchingScope = false;
  }
  let decision =
    !grant || !policy
      ? denied("AUTHORIZATION_REQUIRED")
      : evaluateExecution(
          {
            state: engagement.state,
            currentRevision: engagement.policyRevision,
            grantedRevision: grant.policyRevision,
            scopeMatches: matchingScope,
            revoked: grant.revocation !== null,
            grantStartsAt: grant.validFrom,
            grantExpiresAt: grant.validUntil,
            windowStartsAt: policy.windowStartsAt,
            windowEndsAt: policy.windowEndsAt,
            maxRisk: policy.maxRisk,
            allowedCategories: policy.allowedCategories,
            allowedProtocols: policy.allowedProtocols,
            testerRole: member?.role.name ?? "",
            testerActive: !!member,
            cancelled:
              !!scan.cancelRequestedAt ||
              ["DISABLED", "DRAFT"].includes(scan.target.status) ||
              ["COMPLETED", "COMPLETED_WITH_WARNINGS", "FAILED", "CANCELLED"].includes(scan.state),
          },
          { method: action.method, category: action.category, protocol: action.url.protocol },
          instant,
        );
  if (decision.permitted) {
    try {
      assertDestinationAllowed(action.url, scopePolicyFromTarget(scan.target));
    } catch {
      decision = denied("DESTINATION_OUT_OF_SCOPE");
    }
  }
  if (
    decision.permitted &&
    policy &&
    scan.config &&
    action.phase === "QUEUE" &&
    (scan.config.maxRequests > policy.maxRequests ||
      scan.config.requestsPerSecond > policy.requestsPerSecond ||
      scan.config.concurrency > policy.maxConcurrency)
  )
    decision = denied("SCAN_LIMITS_EXCEED_ROE");
  if (decision.permitted && action.phase === "TRANSPORT" && scan.target.status !== "SCANNING")
    decision = denied("TARGET_NOT_RESERVED");
  if (decision.permitted && policy && consume) {
    if (engagement.requestsMade >= policy.maxRequests)
      decision = denied("ENGAGEMENT_REQUEST_BUDGET_EXHAUSTED");
    else {
      const now = instant.getTime();
      const delay = (engagement.nextRequestAt?.getTime() ?? 0) - now;
      if (delay > 0) return { decision, waitMs: delay };
      await tx.engagement.update({
        where: { id: engagement.id, workspaceId: ctx.workspaceId },
        data: {
          requestsMade: { increment: 1 },
          nextRequestAt: new Date(now + Math.ceil(1000 / policy.requestsPerSecond)),
        },
      });
    }
  }
  await tx.executionDecision.create({
    data: {
      workspaceId: ctx.workspaceId,
      engagementId: engagement.id,
      scanId,
      actorId: ctx.userId,
      grantId: grant?.id ?? null,
      policyRevision: engagement.policyRevision,
      tool: tools[action.category],
      phase: action.phase,
      method: action.method,
      destination: action.url.origin + action.url.pathname,
      ...decision,
    },
  });
  if (!decision.permitted)
    await audit(tx, ctx, "execution.denied", "Scan", scanId, {
      code: decision.code,
      phase: action.phase,
      policyRevision: engagement.policyRevision,
    });
  return { decision, ...(grant ? { grantId: grant.id } : {}) };
}

/** Call inside the same transaction that creates the queue outbox. Return denials so their audit commits. */
export async function authorizeScanQueue(
  tx: DatabaseTransaction,
  ctx: TenantActor,
  scanId: string,
  origin: string,
) {
  const result = await evaluate(
    tx,
    ctx,
    scanId,
    { url: new URL(origin), method: "GET", category: "DISCOVERY", phase: "QUEUE" },
    false,
  );
  if (result.decision.permitted && result.grantId)
    await tx.scan.update({
      where: { id: scanId, workspaceId: ctx.workspaceId },
      data: { authorizationGrantId: result.grantId, executionActorId: ctx.userId },
    });
  return result;
}

/** A database outage, expired grant, revoked membership or modified scope prevents socket creation. */
export function executionRequestGuard(
  prisma: PrismaClient,
  workspaceId: string,
  scanId: string,
  category: TestCategory,
) {
  return async (request: { url: URL; method: string }): Promise<void> => {
    for (;;) {
      const result = await prisma.$transaction(
        async (tx) => {
          const scan = await tx.scan.findFirst({
            where: { id: scanId, workspaceId },
            select: { executionActorId: true },
          });
          if (!scan?.executionActorId) throw new GovernanceError(403, "EXECUTION_ACTOR_REQUIRED");
          return evaluate(
            tx,
            { workspaceId, userId: scan.executionActorId },
            scanId,
            { ...request, category, phase: "TRANSPORT" },
            true,
          );
        },
        { timeout: 15000 },
      );
      if (!result.decision.permitted) throw new GovernanceError(403, result.decision.code);
      if (!result.waitMs) return;
      await new Promise((resolve) => setTimeout(resolve, Math.min(result.waitMs ?? 0, 1000)));
    }
  };
}
