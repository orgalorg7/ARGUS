import { createHash, randomUUID } from "node:crypto";
import type { PrismaClient, Engagement } from "@aasp/database";
import {
  assertEngagementTransition,
  engagementTransitions,
  hasPermission,
  type EngagementState,
} from "@aasp/security-core";
import {
  createClientSchema,
  createEngagementSchema,
  engagementPolicySchema,
  transitionEngagementSchema,
  authorizationGrantSchema,
  authorizationDocumentSchema,
  reasonSchema,
} from "@aasp/schemas";
import { scopePolicyFromTarget } from "@aasp/scope-engine";
import {
  atomic,
  audit,
  GovernanceError,
  lockEngagement,
  requirePermission,
  type DatabaseTransaction,
  type TenantActor,
} from "./context.js";
import { openDocument, sealDocument } from "./documents.js";
import { scopeDigest } from "./execution.js";

function parse<T>(
  schema: {
    safeParse(
      value: unknown,
    ):
      | { success: true; data: T }
      | { success: false; error: { issues: Array<{ message: string }> } };
  },
  input: unknown,
): T {
  const result = schema.safeParse(input);
  if (!result.success)
    throw new GovernanceError(
      400,
      "INVALID_INPUT",
      result.error.issues.map((i) => i.message).join(" "),
    );
  return result.data;
}

const documentSelect = {
  id: true,
  filename: true,
  contentType: true,
  byteLength: true,
  sha256: true,
  uploadedById: true,
  createdAt: true,
} as const;
const terminalScans = [
  "COMPLETED",
  "COMPLETED_WITH_WARNINGS",
  "FAILED",
  "CANCELLED",
  "CREATED",
] as const;

async function move(
  tx: DatabaseTransaction,
  ctx: TenantActor,
  current: Engagement,
  to: EngagementState,
  reason: string,
  authorizationBasis: string,
  grantId?: string,
) {
  assertEngagementTransition(current.state, to);
  const updated = await tx.engagement.update({
    where: { id: current.id, workspaceId: ctx.workspaceId, version: current.version },
    data: { state: to, version: { increment: 1 } },
  });
  await tx.engagementTransition.create({
    data: {
      workspaceId: ctx.workspaceId,
      engagementId: current.id,
      fromState: current.state,
      toState: to,
      actorId: ctx.userId,
      reason,
      authorizationBasis,
      version: updated.version,
      ...(grantId ? { grantId } : {}),
    },
  });
  await audit(tx, ctx, "engagement.transitioned", "Engagement", current.id, {
    from: current.state,
    to,
    reason,
    version: updated.version,
    authorizationBasis,
    grantId: grantId ?? null,
  });
  return updated;
}

async function validGrant(tx: DatabaseTransaction, engagement: Engagement, now: Date) {
  const grant = await tx.authorizationGrant.findFirst({
    where: {
      workspaceId: engagement.workspaceId,
      engagementId: engagement.id,
      policyRevision: engagement.policyRevision,
      validFrom: { lte: now },
      validUntil: { gt: now },
      revocation: null,
    },
    include: {
      policy: {
        include: {
          targets: {
            include: { target: { include: { scopeRules: { where: { enabled: true } } } } },
          },
        },
      },
    },
    orderBy: { createdAt: "desc" },
  });
  if (
    !grant ||
    grant.policy.targets.length === 0 ||
    grant.policy.targets.some(
      (t) => t.scopeRevision !== t.target.scopeRevision || t.scopeDigest !== scopeDigest(t.target),
    )
  )
    throw new GovernanceError(409, "CURRENT_AUTHORIZATION_REQUIRED");
  return grant;
}

/** Business operations resolve membership inside the transaction, including non-HTTP callers. */
export class EngagementService {
  constructor(private readonly prisma: PrismaClient) {}

  async listClients(ctx: TenantActor, after?: string) {
    await requirePermission(this.prisma, ctx, "client.read");
    const rows = await this.prisma.client.findMany({
      where: { workspaceId: ctx.workspaceId, ...(after ? { id: { gt: after } } : {}) },
      orderBy: { id: "asc" },
      take: 101,
    });
    return { items: rows.slice(0, 100), nextCursor: rows.length > 100 ? rows[99]?.id : null };
  }

  createClient(ctx: TenantActor, input: unknown) {
    const data = parse(createClientSchema, input);
    return atomic(this.prisma, async (tx) => {
      await requirePermission(tx, ctx, "client.create");
      const client = await tx.client.create({ data: { workspaceId: ctx.workspaceId, ...data } });
      await audit(tx, ctx, "client.created", "Client", client.id);
      return client;
    });
  }

  async list(ctx: TenantActor, after?: string) {
    await requirePermission(this.prisma, ctx, "engagement.read");
    const rows = await this.prisma.engagement.findMany({
      where: { workspaceId: ctx.workspaceId, ...(after ? { id: { gt: after } } : {}) },
      include: { client: { select: { name: true } } },
      orderBy: { id: "asc" },
      take: 101,
    });
    return { items: rows.slice(0, 100), nextCursor: rows.length > 100 ? rows[99]?.id : null };
  }

  create(ctx: TenantActor, input: unknown) {
    const data = parse(createEngagementSchema, input);
    return atomic(this.prisma, async (tx) => {
      await requirePermission(tx, ctx, "engagement.create");
      const client = await tx.client.findFirst({
        where: { id: data.clientId, workspaceId: ctx.workspaceId },
      });
      if (!client) throw new GovernanceError(404, "CLIENT_NOT_FOUND");
      const engagement = await tx.engagement.create({
        data: { workspaceId: ctx.workspaceId, ...data },
      });
      await audit(tx, ctx, "engagement.created", "Engagement", engagement.id, {
        clientId: client.id,
      });
      return engagement;
    });
  }

  async get(ctx: TenantActor, id: string) {
    const role = await requirePermission(this.prisma, ctx, "engagement.read");
    const engagement = await this.prisma.engagement.findFirst({
      where: { id, workspaceId: ctx.workspaceId },
      include: {
        client: true,
        policies: {
          orderBy: { revision: "desc" },
          take: 1,
          include: {
            targets: {
              include: {
                target: {
                  select: { id: true, name: true, origin: true, status: true, scopeRevision: true },
                },
              },
            },
          },
        },
        documents: { select: documentSelect, orderBy: { createdAt: "desc" }, take: 100 },
        grants: { include: { revocation: true }, orderBy: { createdAt: "desc" }, take: 100 },
        transitions: { orderBy: { version: "desc" }, take: 100 },
        scans: {
          select: { id: true, name: true, state: true, createdAt: true },
          orderBy: { createdAt: "desc" },
          take: 100,
        },
      },
    });
    if (!engagement) throw new GovernanceError(404, "ENGAGEMENT_NOT_FOUND");
    return {
      ...engagement,
      actorRole: role,
      allowedTransitions: hasPermission(role, "engagement.transition")
        ? engagementTransitions[engagement.state].filter((state) => state !== "AUTHORIZED")
        : [],
      canManage: hasPermission(role, "scope.modify"),
      canAuthorize: hasPermission(role, "engagement.authorize"),
      canReadDocuments: hasPermission(role, "evidence.read_sensitive"),
      canExecute: hasPermission(role, "test.execute.safe"),
    };
  }

  configurePolicy(ctx: TenantActor, id: string, input: unknown) {
    const data = parse(engagementPolicySchema, input);
    return atomic(this.prisma, async (tx) => {
      await requirePermission(tx, ctx, "scope.modify");
      const engagement = await lockEngagement(tx, ctx, id, data.expectedVersion);
      if (!["DRAFT", "SCOPING"].includes(engagement.state))
        throw new GovernanceError(409, "RETURN_TO_SCOPING_REQUIRED");
      const targets = await tx.target.findMany({
        where: {
          id: { in: data.targetIds },
          workspaceId: ctx.workspaceId,
          status: { notIn: ["DRAFT", "DISABLED", "SCANNING"] },
        },
        include: { scopeRules: { where: { enabled: true } } },
        orderBy: { id: "asc" },
      });
      if (targets.length !== data.targetIds.length)
        throw new GovernanceError(400, "SCOPE_TARGET_UNAVAILABLE");
      for (const target of targets) scopePolicyFromTarget(target);
      const revision = engagement.policyRevision + 1;
      await tx.engagementPolicy.create({
        data: {
          maxRequests: data.maxRequests,
          requestsPerSecond: data.requestsPerSecond,
          maxConcurrency: data.maxConcurrency,
          maxRisk: data.maxRisk,
          allowedCategories: data.allowedCategories,
          allowedProtocols: data.allowedProtocols,
          restrictions: data.restrictions,
          reason: data.reason,
          windowStartsAt: new Date(data.windowStartsAt),
          windowEndsAt: new Date(data.windowEndsAt),
          workspaceId: ctx.workspaceId,
          engagementId: id,
          revision,
          createdById: ctx.userId,
          targets: {
            create: targets.map((target) => ({
              targetId: target.id,
              scopeRevision: target.scopeRevision,
              scopeDigest: scopeDigest(target),
            })),
          },
        },
      });
      const result = await tx.engagement.update({
        where: { id, workspaceId: ctx.workspaceId, version: data.expectedVersion },
        data: { policyRevision: revision, version: { increment: 1 } },
      });
      await audit(tx, ctx, "engagement.policy_versioned", "Engagement", id, {
        revision,
        targetIds: data.targetIds,
        reason: data.reason,
      });
      return result;
    });
  }

  transition(ctx: TenantActor, id: string, input: unknown) {
    const data = parse(transitionEngagementSchema, input);
    return atomic(this.prisma, async (tx) => {
      const role = await requirePermission(tx, ctx, "engagement.transition");
      const engagement = await lockEngagement(tx, ctx, id, data.expectedVersion);
      if (data.to === "AUTHORIZED") throw new GovernanceError(409, "USE_AUTHORIZATION_GRANT");
      if (
        !(["DRAFT", "SCOPING", "ARCHIVED"] as string[]).includes(data.to) &&
        !engagement.policyRevision
      )
        throw new GovernanceError(409, "ROE_REQUIRED");
      try {
        assertEngagementTransition(engagement.state, data.to);
      } catch (error) {
        throw new GovernanceError(409, "INVALID_TRANSITION", (error as Error).message);
      }
      const running = await tx.scan.count({
        where: {
          workspaceId: ctx.workspaceId,
          engagementId: id,
          state: { notIn: [...terminalScans] },
        },
      });
      if (running && data.to !== "SCOPING")
        throw new GovernanceError(409, "EXECUTIONS_STILL_RUNNING");
      const grant = ["SCHEDULED", "ACTIVE", "TESTING", "RETEST"].includes(data.to)
        ? await validGrant(tx, engagement, new Date())
        : null;
      // Re-scoping stops new transport immediately; in-flight requests retain bounded timeouts.
      if (data.to === "SCOPING")
        await tx.scan.updateMany({
          where: {
            workspaceId: ctx.workspaceId,
            engagementId: id,
            state: { notIn: [...terminalScans] },
          },
          data: { cancelRequestedAt: new Date() },
        });
      return move(
        tx,
        ctx,
        engagement,
        data.to,
        data.reason,
        `${role}:engagement.transition`,
        grant?.id,
      );
    });
  }

  uploadDocument(ctx: TenantActor, id: string, input: unknown) {
    const data = parse(authorizationDocumentSchema, input);
    const content = Buffer.from(data.contentBase64, "base64");
    if (
      !content.length ||
      content.length > 1024 * 1024 ||
      content.toString("base64") !== data.contentBase64
    )
      throw new GovernanceError(400, "INVALID_DOCUMENT_SIZE");
    if (data.contentType === "application/pdf" && content.subarray(0, 5).toString() !== "%PDF-")
      throw new GovernanceError(400, "INVALID_PDF");
    const documentId = randomUUID();
    return atomic(this.prisma, async (tx) => {
      await requirePermission(tx, ctx, "engagement.authorize");
      await lockEngagement(tx, ctx, id);
      const document = await tx.authorizationDocument.create({
        data: {
          id: documentId,
          workspaceId: ctx.workspaceId,
          engagementId: id,
          filename: data.filename,
          contentType: data.contentType,
          byteLength: content.length,
          sha256: createHash("sha256").update(content).digest("hex"),
          encryptedContent: new Uint8Array(
            sealDocument(content, `${ctx.workspaceId}/${id}/${documentId}`),
          ),
          uploadedById: ctx.userId,
        },
        select: documentSelect,
      });
      await audit(
        tx,
        ctx,
        "authorization.document_uploaded",
        "AuthorizationDocument",
        document.id,
        { sha256: document.sha256, byteLength: document.byteLength },
      );
      return document;
    });
  }

  downloadDocument(ctx: TenantActor, id: string, documentId: string) {
    return atomic(this.prisma, async (tx) => {
      await requirePermission(tx, ctx, "evidence.read_sensitive");
      const document = await tx.authorizationDocument.findFirst({
        where: { id: documentId, workspaceId: ctx.workspaceId, engagementId: id },
      });
      if (!document) throw new GovernanceError(404, "DOCUMENT_NOT_FOUND");
      const content = openDocument(
        document.encryptedContent,
        `${ctx.workspaceId}/${id}/${document.id}`,
        document.sha256,
      );
      await audit(
        tx,
        ctx,
        "authorization.document_downloaded",
        "AuthorizationDocument",
        document.id,
        { sha256: document.sha256 },
      );
      return { filename: document.filename, contentType: document.contentType, content };
    });
  }

  authorize(ctx: TenantActor, id: string, input: unknown) {
    const data = parse(authorizationGrantSchema, input);
    return atomic(this.prisma, async (tx) => {
      const role = await requirePermission(tx, ctx, "engagement.authorize");
      const engagement = await lockEngagement(tx, ctx, id, data.expectedVersion);
      if (engagement.state !== "AWAITING_AUTHORIZATION")
        throw new GovernanceError(409, "ENGAGEMENT_NOT_AWAITING_AUTHORIZATION");
      const policy = await tx.engagementPolicy.findUnique({
        where: {
          workspaceId_engagementId_revision: {
            workspaceId: ctx.workspaceId,
            engagementId: id,
            revision: engagement.policyRevision,
          },
        },
        include: {
          targets: {
            include: { target: { include: { scopeRules: { where: { enabled: true } } } } },
          },
        },
      });
      if (
        !policy ||
        !policy.targets.length ||
        policy.targets.some(
          (t) =>
            t.scopeRevision !== t.target.scopeRevision || t.scopeDigest !== scopeDigest(t.target),
        )
      )
        throw new GovernanceError(409, "SCOPE_CHANGED_REVISE_ROE");
      if (
        new Date(data.validFrom) > policy.windowStartsAt ||
        new Date(data.validUntil) < policy.windowEndsAt ||
        new Date(data.validUntil) <= new Date()
      )
        throw new GovernanceError(400, "GRANT_MUST_COVER_TESTING_WINDOW");
      const document = await tx.authorizationDocument.findFirst({
        where: { id: data.documentId, workspaceId: ctx.workspaceId, engagementId: id },
      });
      if (!document) throw new GovernanceError(404, "DOCUMENT_NOT_FOUND");
      openDocument(
        document.encryptedContent,
        `${ctx.workspaceId}/${id}/${document.id}`,
        document.sha256,
      );
      const grant = await tx.authorizationGrant.create({
        data: {
          workspaceId: ctx.workspaceId,
          engagementId: id,
          policyRevision: policy.revision,
          documentId: document.id,
          authorizedBy: data.authorizedBy,
          approvedById: ctx.userId,
          validFrom: new Date(data.validFrom),
          validUntil: new Date(data.validUntil),
          reason: data.reason,
        },
      });
      await audit(tx, ctx, "authorization.granted", "AuthorizationGrant", grant.id, {
        documentSha256: document.sha256,
        policyRevision: policy.revision,
        reason: data.reason,
      });
      const updated = await move(
        tx,
        ctx,
        engagement,
        "AUTHORIZED",
        data.reason,
        `${role}:engagement.authorize`,
        grant.id,
      );
      return { engagement: updated, grant };
    });
  }

  revoke(ctx: TenantActor, id: string, grantId: string, input: unknown) {
    const reason = parse(reasonSchema, input);
    return atomic(this.prisma, async (tx) => {
      await requirePermission(tx, ctx, "engagement.authorize");
      await lockEngagement(tx, ctx, id);
      const grant = await tx.authorizationGrant.findFirst({
        where: { id: grantId, workspaceId: ctx.workspaceId, engagementId: id },
      });
      if (!grant) throw new GovernanceError(404, "AUTHORIZATION_NOT_FOUND");
      const revocation = await tx.authorizationRevocation.create({
        data: { grantId, actorId: ctx.userId, reason },
      });
      await tx.scan.updateMany({
        where: {
          workspaceId: ctx.workspaceId,
          engagementId: id,
          authorizationGrantId: grantId,
          state: { notIn: [...terminalScans] },
        },
        data: { cancelRequestedAt: new Date() },
      });
      await audit(tx, ctx, "authorization.revoked", "AuthorizationGrant", grantId, { reason });
      return revocation;
    });
  }

  async decisions(ctx: TenantActor, id: string, after?: string) {
    await requirePermission(this.prisma, ctx, "engagement.read");
    const rows = await this.prisma.executionDecision.findMany({
      where: {
        workspaceId: ctx.workspaceId,
        engagementId: id,
        ...(after ? { id: { gt: after } } : {}),
      },
      take: 101,
      orderBy: { id: "asc" },
    });
    return { items: rows.slice(0, 100), nextCursor: rows.length > 100 ? rows[99]?.id : null };
  }
}
