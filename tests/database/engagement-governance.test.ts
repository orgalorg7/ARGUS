import { randomBytes, randomUUID, createHash } from "node:crypto";
import { createServer } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PrismaClient, WorkspaceRole } from "@aasp/database";
import {
  EngagementService,
  authorizeScanQueue,
  executionRequestGuard,
  type TenantActor,
} from "@aasp/engagement-engine";
import { ScopeEngine, ScopedHttpClient, scopePolicyFromTarget } from "@aasp/scope-engine";

const databaseUrl = process.env["AASP_TEST_DATABASE_URL"];
if (!databaseUrl || !new URL(databaseUrl).pathname.endsWith("_test"))
  throw new Error(
    "AASP_TEST_DATABASE_URL must name an isolated database ending in _test. Apply migrations first.",
  );
const db = new PrismaClient({ datasourceUrl: databaseUrl });
const service = new EngagementService(db);
const vaultKey = process.env["EVIDENCE_ENCRYPTION_KEY"];
const reason = "Approved synthetic assessment for integration verification.";
const from = new Date(Date.now() - 3600000).toISOString();
const until = new Date(Date.now() + 3600000).toISOString();
let requests = 0;
let origin: string;
const server = createServer((_request, response) => {
  requests += 1;
  response.end("synthetic authorized fixture");
});

beforeAll(async () => {
  process.env["EVIDENCE_ENCRYPTION_KEY"] = randomBytes(32).toString("base64");
  await db.$connect();
  for (const name of Object.values(WorkspaceRole))
    await db.role.upsert({ where: { name }, create: { name, description: name }, update: {} });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Fixture did not bind");
  origin = `http://127.0.0.1:${address.port}`;
});
afterAll(async () => {
  await new Promise<void>((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
  await db.$disconnect();
  if (vaultKey === undefined) delete process.env["EVIDENCE_ENCRYPTION_KEY"];
  else process.env["EVIDENCE_ENCRYPTION_KEY"] = vaultKey;
});

async function tenant() {
  const user = await db.user.create({
    data: {
      email: `${randomUUID()}@synthetic.test`,
      displayName: "Test owner",
      passwordHash: "not-used-for-login",
    },
  });
  const organization = await db.organization.create({
    data: {
      name: "Synthetic security company",
      members: { create: { userId: user.id, role: "OWNER" } },
    },
  });
  const role = await db.role.findUniqueOrThrow({ where: { name: "OWNER" } });
  const workspace = await db.workspace.create({
    data: {
      name: "Synthetic workspace",
      slug: randomUUID(),
      organizationId: organization.id,
      members: { create: { userId: user.id, roleId: role.id } },
    },
  });
  const ctx = { workspaceId: workspace.id, userId: user.id };
  const client = await service.createClient(ctx, {
    name: "NORTHSTAR FINANCIAL",
    legalName: "Synthetic Northstar Financial",
  });
  const engagement = await service.create(ctx, {
    clientId: client.id,
    name: "API SECURITY ASSESSMENT",
    objective: "Validate synthetic authorization controls.",
    environment: "LAB",
  });
  const port = new URL(origin).port;
  const target = await db.target.create({
    data: {
      workspaceId: workspace.id,
      createdById: user.id,
      name: "Owned loopback fixture",
      origin,
      normalizedHostname: "127.0.0.1",
      normalizedPort: Number(port),
      status: "READY",
      allowPrivateNetwork: true,
      scopeRules: {
        create: [
          { type: "HOST", value: "127.0.0.1" },
          { type: "PORT", value: port },
        ],
      },
    },
    include: { scopeRules: true },
  });
  return { ctx, engagement, target, organization, client };
}

function policyInput(targetId: string, version: number, maxRequests = 20) {
  return {
    expectedVersion: version,
    reason,
    targetIds: [targetId],
    windowStartsAt: from,
    windowEndsAt: until,
    maxRequests,
    requestsPerSecond: 20,
    maxConcurrency: 2,
    maxRisk: "LOW_IMPACT",
    allowedCategories: ["DISCOVERY", "HTTP_CONFIGURATION", "AUTHORIZATION"],
    allowedProtocols: ["http:"],
    restrictions: "Only the synthetic loopback fixture is authorized. No mutations.",
  };
}

async function authorized(maxRequests = 20) {
  const f = await tenant();
  let engagement = await service.configurePolicy(
    f.ctx,
    f.engagement.id,
    policyInput(f.target.id, 1, maxRequests),
  );
  for (const to of ["SCOPING", "AWAITING_AUTHORIZATION"])
    engagement = await service.transition(f.ctx, engagement.id, {
      to,
      expectedVersion: engagement.version,
      reason,
    });
  const original = Buffer.from("SYNTHETIC TEST AUTHORIZATION. Owned loopback fixture only.");
  const document = await service.uploadDocument(f.ctx, engagement.id, {
    filename: "authorization.txt",
    contentType: "text/plain",
    contentBase64: original.toString("base64"),
  });
  const result = await service.authorize(f.ctx, engagement.id, {
    expectedVersion: engagement.version,
    reason,
    documentId: document.id,
    authorizedBy: "Synthetic client signatory",
    validFrom: from,
    validUntil: until,
  });
  engagement = result.engagement;
  for (const to of ["SCHEDULED", "ACTIVE", "TESTING"])
    engagement = await service.transition(f.ctx, engagement.id, {
      to,
      expectedVersion: engagement.version,
      reason,
    });
  const scan = await db.scan.create({
    data: {
      workspaceId: f.ctx.workspaceId,
      engagementId: engagement.id,
      targetId: f.target.id,
      createdById: f.ctx.userId,
      name: "Synthetic tool execution",
      config: {
        create: {
          profile: "LIGHT",
          crawlDepth: 0,
          maxUrls: 1,
          maxRequests,
          requestsPerSecond: 20,
          concurrency: 2,
          timeoutMs: 1000,
          followRedirects: false,
          includeSubdomains: false,
        },
      },
    },
  });
  return { ...f, engagement, grant: result.grant, document, original, scan };
}

async function queue(f: Awaited<ReturnType<typeof authorized>>) {
  return db.$transaction(async (tx) => {
    const result = await authorizeScanQueue(tx, f.ctx, f.scan.id, origin);
    if (result.decision.permitted) {
      await tx.scan.update({ where: { id: f.scan.id }, data: { state: "QUEUED" } });
      await tx.target.update({ where: { id: f.target.id }, data: { status: "SCANNING" } });
    }
    return result;
  });
}

function clientFor(f: Awaited<ReturnType<typeof authorized>>) {
  return new ScopedHttpClient(new ScopeEngine(), scopePolicyFromTarget(f.target), {
    allowedMethods: ["GET", "DELETE"],
    beforeRequest: executionRequestGuard(db, f.ctx.workspaceId, f.scan.id, "DISCOVERY"),
  });
}

async function addMember(ctx: TenantActor, organizationId: string, name: WorkspaceRole) {
  const user = await db.user.create({
    data: {
      email: `${randomUUID()}@synthetic.test`,
      displayName: name,
      passwordHash: "not-used-for-login",
    },
  });
  const role = await db.role.findUniqueOrThrow({ where: { name } });
  await db.organizationMember.create({ data: { organizationId, userId: user.id, role: name } });
  await db.workspaceMember.create({
    data: { workspaceId: ctx.workspaceId, userId: user.id, roleId: role.id },
  });
  return { ...ctx, userId: user.id };
}

describe("PostgreSQL engagement governance invariants", () => {
  it("isolates organization data, including supplied resource and workspace IDs", async () => {
    const a = await tenant();
    const b = await tenant();
    await expect(service.get(a.ctx, b.engagement.id)).rejects.toMatchObject({ status: 404 });
    await expect(
      service.get({ ...a.ctx, workspaceId: b.ctx.workspaceId }, b.engagement.id),
    ).rejects.toMatchObject({ status: 403 });
    expect(
      (await service.list(a.ctx)).items.every((item) => item.workspaceId === a.ctx.workspaceId),
    ).toBe(true);
    await expect(
      service.create(a.ctx, {
        clientId: b.client.id,
        name: "Cross-tenant engagement",
        objective: reason,
        environment: "LAB",
      }),
    ).rejects.toMatchObject({ status: 404 });
    expect(() =>
      service.createClient(a.ctx, {
        name: "Injection",
        legalName: "Injection",
        workspaceId: b.ctx.workspaceId,
      }),
    ).toThrow("Unrecognized key");
  });

  it("rejects cross-tenant foreign keys even when the API is bypassed", async () => {
    const a = await tenant();
    const b = await tenant();
    await expect(
      db.scan.create({
        data: {
          workspaceId: a.ctx.workspaceId,
          targetId: b.target.id,
          createdById: a.ctx.userId,
          name: "Invalid tenant",
        },
      }),
    ).rejects.toMatchObject({ code: "P2003" });
    await expect(
      db.engagement.create({
        data: {
          workspaceId: a.ctx.workspaceId,
          clientId: b.client.id,
          name: "Invalid client",
          objective: reason,
          environment: "LAB",
        },
      }),
    ).rejects.toMatchObject({ code: "P2003" });
  });

  it("keeps client roles out of internal records and prevents analyst scope/authorization changes", async () => {
    const f = await tenant();
    const client = await addMember(f.ctx, f.organization.id, "CLIENT_USER");
    const analyst = await addMember(f.ctx, f.organization.id, "ANALYST");
    await expect(service.get(client, f.engagement.id)).rejects.toMatchObject({ status: 403 });
    await expect(
      service.configurePolicy(analyst, f.engagement.id, policyInput(f.target.id, 1)),
    ).rejects.toMatchObject({ status: 403 });
    await expect(
      service.uploadDocument(analyst, f.engagement.id, {
        filename: "forged.txt",
        contentType: "text/plain",
        contentBase64: Buffer.from(reason).toString("base64"),
      }),
    ).rejects.toMatchObject({ status: 403 });
  });

  it("requires an authorization grant at queue admission and preserves a denial audit", async () => {
    const f = await tenant();
    const scan = await db.scan.create({
      data: {
        workspaceId: f.ctx.workspaceId,
        targetId: f.target.id,
        createdById: f.ctx.userId,
        name: "Legacy history",
      },
    });
    const result = await db.$transaction((tx) => authorizeScanQueue(tx, f.ctx, scan.id, origin));
    expect(result.decision).toMatchObject({ permitted: false, code: "ENGAGEMENT_REQUIRED" });
    expect(
      await db.auditEvent.count({ where: { resourceId: scan.id, action: "execution.denied" } }),
    ).toBe(1);
    expect(await db.scanJob.count({ where: { scanId: scan.id } })).toBe(0);
  });

  it("preserves encrypted originals and prevents cross-engagement download or mutation", async () => {
    const f = await authorized();
    const other = await tenant();
    const row = await db.authorizationDocument.findUniqueOrThrow({ where: { id: f.document.id } });
    expect(Buffer.from(row.encryptedContent).includes(f.original)).toBe(false);
    expect(row.sha256).toBe(createHash("sha256").update(f.original).digest("hex"));
    expect((await service.downloadDocument(f.ctx, f.engagement.id, f.document.id)).content).toEqual(
      f.original,
    );
    await expect(
      service.downloadDocument(other.ctx, other.engagement.id, f.document.id),
    ).rejects.toMatchObject({ status: 404 });
    await expect(
      db.authorizationDocument.update({ where: { id: row.id }, data: { sha256: "0".repeat(64) } }),
    ).rejects.toThrow();
    await expect(db.authorizationGrant.delete({ where: { id: f.grant.id } })).rejects.toThrow();
  });

  it("commits lifecycle history with actor and audit, and rejects direct unaudited state changes", async () => {
    const f = await authorized();
    const history = await db.engagementTransition.findMany({
      where: { engagementId: f.engagement.id },
    });
    expect(history.map((item) => item.toState)).toEqual([
      "SCOPING",
      "AWAITING_AUTHORIZATION",
      "AUTHORIZED",
      "SCHEDULED",
      "ACTIVE",
      "TESTING",
    ]);
    expect(
      history.every((item) => item.actorId === f.ctx.userId && !!item.authorizationBasis),
    ).toBe(true);
    expect(
      await db.auditEvent.count({
        where: { resourceId: f.engagement.id, action: "engagement.transitioned" },
      }),
    ).toBe(history.length);
    await expect(
      db.engagement.update({
        where: { id: f.engagement.id },
        data: { state: "COMPLETED", version: { increment: 1 } },
      }),
    ).rejects.toThrow();
    expect((await service.get(f.ctx, f.engagement.id)).state).toBe("TESTING");
  });

  it("allows one of two concurrent policy changes and retains the old revision", async () => {
    const f = await tenant();
    const results = await Promise.allSettled([
      service.configurePolicy(f.ctx, f.engagement.id, policyInput(f.target.id, 1)),
      service.configurePolicy(f.ctx, f.engagement.id, policyInput(f.target.id, 1)),
    ]);
    expect(results.filter((item) => item.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((item) => item.status === "rejected")).toHaveLength(1);
    expect(await db.engagementPolicy.count({ where: { engagementId: f.engagement.id } })).toBe(1);
    await expect(
      db.engagementPolicy.updateMany({
        where: { engagementId: f.engagement.id },
        data: { maxRequests: 999 },
      }),
    ).rejects.toThrow();
  });

  it("blocks revocation before the next socket is created", async () => {
    const f = await authorized();
    expect((await queue(f)).decision.permitted).toBe(true);
    const client = clientFor(f);
    await client.request(origin);
    const before = requests;
    await service.revoke(f.ctx, f.engagement.id, f.grant.id, reason);
    await expect(client.request(origin)).rejects.toThrow();
    expect(requests).toBe(before);
    expect(
      await db.executionDecision.count({ where: { scanId: f.scan.id, permitted: false } }),
    ).toBe(1);
  });

  it("rejects membership revocation and current scope changes at execution time", async () => {
    const f = await authorized();
    await queue(f);
    const client = clientFor(f);
    await db.target.update({
      where: { id: f.target.id },
      data: { scopeRevision: { increment: 1 } },
    });
    const before = requests;
    await expect(client.request(origin)).rejects.toMatchObject({ code: "AUTHORIZATION_STALE" });
    await db.workspaceMember.deleteMany({
      where: { workspaceId: f.ctx.workspaceId, userId: f.ctx.userId },
    });
    await expect(client.request(origin)).rejects.toMatchObject({
      code: "TESTER_PERMISSION_DENIED",
    });
    expect(requests).toBe(before);
  });

  it("rejects a mutating method despite explicit caller capability and an owner role", async () => {
    const f = await authorized();
    await queue(f);
    const before = requests;
    await expect(clientFor(f).request(origin, { method: "DELETE" })).rejects.toMatchObject({
      code: "SENSITIVE_CAPABILITY_NOT_ENABLED",
    });
    expect(requests).toBe(before);
  });

  it("checks the actual destination even if a worker supplies a broader HTTP scope", async () => {
    const f = await authorized();
    await queue(f);
    const before = requests;
    const client = new ScopedHttpClient(
      new ScopeEngine(),
      { ...scopePolicyFromTarget(f.target), allowedDomains: ["localhost"] },
      {
        beforeRequest: executionRequestGuard(db, f.ctx.workspaceId, f.scan.id, "DISCOVERY"),
      },
    );
    await expect(client.request(origin.replace("127.0.0.1", "localhost"))).rejects.toMatchObject({
      code: "DESTINATION_OUT_OF_SCOPE",
    });
    expect(requests).toBe(before);
  });

  it("rejects an expired persisted grant using database time", async () => {
    const f = await authorized();
    await queue(f);
    const before = requests;
    const expired = await db.authorizationGrant.create({
      data: {
        workspaceId: f.ctx.workspaceId,
        engagementId: f.engagement.id,
        policyRevision: f.engagement.policyRevision,
        documentId: f.document.id,
        approvedById: f.ctx.userId,
        authorizedBy: "Synthetic owner",
        validFrom: new Date(Date.now() - 7200000),
        validUntil: new Date(Date.now() - 3600000),
        reason,
      },
    });
    await db.scan.update({ where: { id: f.scan.id }, data: { authorizationGrantId: expired.id } });
    await expect(clientFor(f).request(origin)).rejects.toMatchObject({
      code: "AUTHORIZATION_OUTSIDE_WINDOW",
    });
    expect(requests).toBe(before);
  });

  it("shares request limits across independent concurrent worker transports", async () => {
    const f = await authorized(2);
    await queue(f);
    const before = requests;
    const results = await Promise.allSettled([
      clientFor(f).request(origin),
      clientFor(f).request(origin),
      clientFor(f).request(origin),
    ]);
    expect(results.filter((item) => item.status === "fulfilled")).toHaveLength(2);
    expect(results.filter((item) => item.status === "rejected")).toHaveLength(1);
    expect(requests - before).toBe(2);
    expect(
      (await db.engagement.findUniqueOrThrow({ where: { id: f.engagement.id } })).requestsMade,
    ).toBe(2);
  });

  it("enforces evidence tenant links and append-only custody", async () => {
    const a = await authorized();
    const b = await authorized();
    const evidence = await db.evidence.create({
      data: {
        workspaceId: b.ctx.workspaceId,
        scanId: b.scan.id,
        source: "synthetic",
        asset: origin,
        requestMetadata: {},
        responseMetadata: {},
        redactedExcerpt: "fixture",
        hash: "a".repeat(64),
      },
    });
    await expect(
      db.evidence.create({
        data: {
          workspaceId: a.ctx.workspaceId,
          scanId: b.scan.id,
          source: "synthetic",
          asset: origin,
          requestMetadata: {},
          responseMetadata: {},
          redactedExcerpt: "fixture",
          hash: "a".repeat(64),
        },
      }),
    ).rejects.toMatchObject({ code: "P2003" });
    const finding = await db.finding.create({
      data: {
        workspaceId: a.ctx.workspaceId,
        scanId: a.scan.id,
        publicId: "SYN-1",
        title: "Synthetic observation",
        category: "TEST",
        severity: "INFO",
        confidence: 0.9,
        asset: origin,
        description: reason,
        technicalImpact: reason,
        businessImpact: reason,
        remediation: reason,
        correlationKey: "synthetic",
      },
    });
    await expect(
      db.findingEvidence.create({ data: { findingId: finding.id, evidenceId: evidence.id } }),
    ).rejects.toThrow();
    await expect(
      db.evidence.update({ where: { id: evidence.id }, data: { redactedExcerpt: "rewritten" } }),
    ).rejects.toThrow();
    await expect(
      db.auditEvent.deleteMany({ where: { workspaceId: a.ctx.workspaceId } }),
    ).rejects.toThrow();
  });
});
