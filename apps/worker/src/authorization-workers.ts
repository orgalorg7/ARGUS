import { executionRequestGuard } from "@aasp/engagement-engine";
import type { PrismaClient } from "@aasp/database";
import {
  IdentityAuthenticationState,
  JobStatus,
  ScanState,
  StageStatus,
  TargetStatus,
} from "@aasp/database";
import type { Prisma } from "@aasp/database";
import {
  AuthorizationMatrixEngine,
  IdentityRequestContext,
  ResourceOwnershipGraph,
  StaticIdentityProvider,
  authorizationFindingFingerprint,
  decryptCredential,
  safeAuthenticationError,
  type AssessmentIdentity,
  type AuthorizationTestCase,
  type AuthorizationTransport,
  type AuthorizedResource,
  type CredentialMaterial,
  type EncryptedSecret,
  type PreparedIdentity,
} from "@aasp/authorization-engine";
import { EvidenceEngine } from "@aasp/evidence-engine";
import { logger } from "@aasp/logger";
import { ScopeEngine, ScopedHttpClient, scopePolicyFromTarget } from "@aasp/scope-engine";
import type { ScannerObservationInput } from "@aasp/schemas";
import { Queue, Worker } from "bullmq";
import { Redis } from "ioredis";

interface StagePayload {
  workspaceId: string;
  scanId: string;
}

interface WorkerContext {
  prisma: PrismaClient;
  redisUrl: string;
  workerId: string;
}

export interface AuthorizationWorkerRuntime {
  close(): Promise<void>;
}

const authorizationQueueName = "scan.authorization";
const normalizeQueueName = "scan.normalize";

function jsonValue(value: unknown): Prisma.InputJsonValue {
  return JSON.parse(JSON.stringify(value)) as Prisma.InputJsonValue;
}

function record(value: Prisma.JsonValue | null): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function strings(value: unknown): Record<string, string> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return Object.fromEntries(
    Object.entries(value).filter(
      (entry): entry is [string, string] => typeof entry[1] === "string",
    ),
  );
}

function publicIdentity(identity: {
  id: string;
  label: string;
  role: string;
  tenant: string | null;
  authenticationType: AssessmentIdentity["authenticationType"];
  authenticationState: AssessmentIdentity["authenticationState"];
  metadata: Prisma.JsonValue | null;
  enabled: boolean;
}): AssessmentIdentity {
  return {
    id: identity.id,
    label: identity.label,
    role: identity.role,
    tenant: identity.tenant,
    authenticationType: identity.authenticationType,
    credentialReference: null,
    authenticationState: identity.authenticationState,
    metadata: record(identity.metadata),
    enabled: identity.enabled,
  };
}

function resourceValue(resource: {
  id: string;
  resourceType: string;
  externalId: string;
  tenant: string | null;
  ownerIdentityId: string | null;
  provenance: AuthorizedResource["provenance"];
  endpointVariables: Prisma.JsonValue | null;
  metadata: Prisma.JsonValue | null;
}): AuthorizedResource {
  return {
    id: resource.id,
    type: resource.resourceType,
    externalId: resource.externalId,
    tenant: resource.tenant,
    ownerIdentityId: resource.ownerIdentityId,
    provenance: resource.provenance,
    endpointVariables: strings(resource.endpointVariables),
    metadata: record(resource.metadata),
  };
}

function decryptRequestBody(
  value: Prisma.JsonValue | null,
  key: string | undefined,
): string | undefined {
  if (!value) return undefined;
  if (!key) throw new Error("Identity secret encryption key is unavailable.");
  const material = decryptCredential(value as unknown as EncryptedSecret, key);
  if (material.type !== "CUSTOM_HEADERS")
    throw new Error("Encrypted test body has an invalid envelope.");
  return material.headers["x-encrypted-request-body"];
}

function testCaseValue(
  testCase: {
    id: string;
    name: string;
    resourceId: string;
    action: string;
    endpointTemplate: string;
    method: string;
    identityIds: string[];
    expectedPolicy: Prisma.JsonValue;
    mutationRisk: AuthorizationTestCase["mutationRisk"];
    mutationExplicitlyAuthorized: boolean;
    cleanupStrategy: AuthorizationTestCase["cleanupStrategy"];
    requestHeaders: Prisma.JsonValue | null;
    encryptedRequestBody: Prisma.JsonValue | null;
    contentType: string | null;
    followRedirects: boolean;
    timingSamples: number;
  },
  encryptionKey: string | undefined,
): AuthorizationTestCase {
  const requestBody = testCase.encryptedRequestBody
    ? decryptRequestBody(testCase.encryptedRequestBody, encryptionKey)
    : undefined;
  return {
    id: testCase.id,
    name: testCase.name,
    resourceId: testCase.resourceId,
    action: testCase.action,
    endpointTemplate: testCase.endpointTemplate,
    method: testCase.method as AuthorizationTestCase["method"],
    identityIds: testCase.identityIds,
    expectedPolicy: record(testCase.expectedPolicy) as Record<string, "ALLOW" | "DENY" | "UNKNOWN">,
    mutationRisk: testCase.mutationRisk,
    mutationExplicitlyAuthorized: testCase.mutationExplicitlyAuthorized,
    cleanupStrategy: testCase.cleanupStrategy,
    requestHeaders: strings(testCase.requestHeaders),
    ...(typeof requestBody === "string" ? { requestBody } : {}),
    ...(testCase.contentType ? { contentType: testCase.contentType } : {}),
    followRedirects: testCase.followRedirects,
    timingSamples: testCase.timingSamples,
  };
}

function observationForDifference(
  testCase: AuthorizationTestCase,
  result: Awaited<ReturnType<AuthorizationMatrixEngine["execute"]>>,
  difference: (typeof result.differences)[number],
): ScannerObservationInput | null {
  if (
    !difference.classification.startsWith("POTENTIAL_") &&
    difference.classification !== "AUTHENTICATION_INCONSISTENCY"
  )
    return null;
  const baseline = result.observations.find(
    ({ identityId }) => identityId === difference.baselineIdentityId,
  );
  const comparison = result.observations.find(
    ({ identityId }) => identityId === difference.comparisonIdentityId,
  );
  if (!baseline || !comparison) return null;
  const observationType =
    difference.classification === "POTENTIAL_HORIZONTAL_BYPASS"
      ? "POTENTIAL_HORIZONTAL_AUTHORIZATION_FAILURE"
      : difference.classification === "POTENTIAL_VERTICAL_BYPASS"
        ? "POTENTIAL_VERTICAL_AUTHORIZATION_FAILURE"
        : difference.classification === "POTENTIAL_TENANT_BYPASS"
          ? "POTENTIAL_TENANT_ISOLATION_FAILURE"
          : difference.classification === "AUTHENTICATION_INCONSISTENCY"
            ? "AUTHENTICATION_STATE_INCONSISTENCY"
            : null;
  if (!observationType) return null;
  return {
    scanner: "aasp-authorization-matrix",
    scannerVersion: "1.0.0",
    observationType,
    asset: new URL(comparison.requestedUrl).origin,
    endpoint: testCase.endpointTemplate,
    method: testCase.method,
    rawSeverity: difference.severity,
    metadata: {
      testCaseId: testCase.id,
      resourceType: result.resource.type,
      resourceProvenance: result.resource.provenance,
      relationship: difference.relationship,
      baselineIdentity: {
        id: baseline.identityId,
        label: baseline.identityLabel,
        role: baseline.identityRole,
        tenant: baseline.identityTenant,
      },
      comparisonIdentity: {
        id: comparison.identityId,
        label: comparison.identityLabel,
        role: comparison.identityRole,
        tenant: comparison.identityTenant,
      },
      expected: comparison.expected,
      classification: difference.classification,
      confidence: difference.confidence,
      confidenceLabel: difference.confidenceLabel,
      statusEquivalent: difference.statusEquivalent,
      structuralSimilarity: difference.structuralSimilarity,
      sensitiveFieldPaths: difference.sensitiveFieldOverlap,
      redirectEquivalent: difference.redirectEquivalent,
      reasons: difference.reasons,
      groupedFindingFingerprint: authorizationFindingFingerprint({
        endpointTemplate: testCase.endpointTemplate,
        method: testCase.method,
        resourceType: result.resource.type,
        classification: difference.classification,
        relationship: difference.relationship,
        tenantRelationship:
          baseline.identityTenant === comparison.identityTenant ? "SAME_TENANT" : "CROSS_TENANT",
      }),
    },
    evidence: [
      {
        source: "authorization-matrix-differential",
        asset: comparison.requestedUrl,
        requestMetadata: {
          method: testCase.method,
          endpointTemplate: testCase.endpointTemplate,
          resourceProvenance: result.resource.provenance,
          identityId: comparison.identityId,
          correlationId: result.correlationId,
        },
        responseMetadata: {
          baseline: {
            statusCode: baseline.response.statusCode,
            normalizedBodyHash: baseline.response.normalizedBodyHash,
            fieldPaths: baseline.response.jsonFieldPaths,
          },
          comparison: {
            statusCode: comparison.response.statusCode,
            normalizedBodyHash: comparison.response.normalizedBodyHash,
            fieldPaths: comparison.response.jsonFieldPaths,
          },
          structuralSimilarity: difference.structuralSimilarity,
          sensitiveFieldPaths: difference.sensitiveFieldOverlap,
          redirectEquivalent: difference.redirectEquivalent,
        },
        excerpt: `Expected ${comparison.expected}; observed ${comparison.response.statusCode}. Normalized structural similarity ${difference.structuralSimilarity}. Sensitive values were not retained.`,
      },
    ],
  };
}

export function startAuthorizationWorkers(context: WorkerContext): AuthorizationWorkerRuntime {
  const { prisma, redisUrl, workerId } = context;
  const connection = new Redis(redisUrl, { maxRetriesPerRequest: null, enableReadyCheck: true });
  const publisher = new Redis(redisUrl, { maxRetriesPerRequest: null, enableReadyCheck: true });
  const normalizeQueue = new Queue<StagePayload>(normalizeQueueName, { connection: publisher });
  const evidence = new EvidenceEngine(prisma);

  const worker = new Worker<StagePayload>(
    authorizationQueueName,
    async (job) => {
      const scan = await prisma.scan.findFirst({
        where: { id: job.data.scanId, workspaceId: job.data.workspaceId },
        include: {
          config: true,
          target: {
            include: {
              scopeRules: { where: { enabled: true } },
              assessmentIdentities: { where: { enabled: true }, orderBy: { label: "asc" } },
              authorizedResources: {
                where: { enabled: true },
                include: { relationships: true },
              },
              authorizationTestCases: { where: { enabled: true }, orderBy: { createdAt: "asc" } },
            },
          },
        },
      });
      if (!scan?.config) throw new Error("Authorization stage could not load scan configuration.");
      if (scan.state !== ScanState.AUTHORIZATION_ANALYSIS) {
        throw new Error(
          `Authorization analysis expected AUTHORIZATION_ANALYSIS, observed ${scan.state}.`,
        );
      }
      if (scan.target.status !== TargetStatus.SCANNING)
        throw new Error("Target is not reserved for scanning.");
      await prisma.$transaction([
        prisma.scanJob.update({
          where: { id: String(job.id ?? "") },
          data: {
            status: JobStatus.RUNNING,
            attempt: { increment: 1 },
            startedAt: new Date(),
            lockedBy: workerId,
          },
        }),
        prisma.scanStage.update({
          where: { scanId_name: { scanId: scan.id, name: ScanState.AUTHORIZATION_ANALYSIS } },
          data: { status: StageStatus.RUNNING, startedAt: new Date(), errorMessage: null },
        }),
      ]);

      const graph = new ResourceOwnershipGraph();
      const identities = scan.target.assessmentIdentities.map(publicIdentity);
      for (const identity of identities) graph.addIdentity(identity);
      for (const persisted of scan.target.authorizedResources) {
        graph.addResource(resourceValue(persisted));
        for (const relationship of persisted.relationships) {
          graph.addEdge({
            identityId: relationship.identityId,
            resourceId: persisted.id,
            relationship: relationship.relationship,
          });
        }
      }
      const prepared = new Map<string, PreparedIdentity>();
      const failures: Array<{ identityId: string; reason: string }> = [];
      const provider = new StaticIdentityProvider();
      const secretKey = process.env["IDENTITY_SECRET_ENCRYPTION_KEY"];
      for (const persisted of scan.target.assessmentIdentities) {
        const identity = publicIdentity(persisted);
        const requestContext = new IdentityRequestContext(identity);
        try {
          const material: CredentialMaterial =
            identity.authenticationType === "ANONYMOUS"
              ? { type: "ANONYMOUS" }
              : secretKey && persisted.encryptedCredential
                ? decryptCredential(
                    persisted.encryptedCredential as unknown as EncryptedSecret,
                    secretKey,
                  )
                : (() => {
                    throw new Error("Encrypted identity material is unavailable.");
                  })();
          const authentication = await provider.authenticate(identity, material, requestContext);
          const authenticatedIdentity = { ...identity, authenticationState: authentication.state };
          await prisma.assessmentIdentity.update({
            where: { id: identity.id },
            data: {
              authenticationState: authentication.state,
              lastAuthenticatedAt: authentication.authenticatedAt
                ? new Date(authentication.authenticatedAt)
                : null,
              lastFailureReason: authentication.safeReason,
            },
          });
          if (["AUTH_FAILED", "UNAVAILABLE"].includes(authentication.state)) {
            failures.push({
              identityId: identity.id,
              reason: authentication.safeReason ?? "Provider unavailable.",
            });
          } else {
            prepared.set(identity.id, { identity: authenticatedIdentity, context: requestContext });
          }
          logger.info("identity.authenticated", {
            workspaceId: scan.workspaceId,
            scanId: scan.id,
            identityId: identity.id,
            authenticationState: authentication.state,
          });
        } catch (error) {
          const reason = safeAuthenticationError(error);
          failures.push({ identityId: identity.id, reason });
          await prisma.assessmentIdentity.update({
            where: { id: identity.id },
            data: {
              authenticationState: IdentityAuthenticationState.AUTH_FAILED,
              lastFailureReason: reason,
            },
          });
          logger.warn("identity.authentication_failed", {
            workspaceId: scan.workspaceId,
            scanId: scan.id,
            identityId: identity.id,
            reason,
          });
        }
      }

      const scope = scopePolicyFromTarget(scan.target);
      const authorizationScopeEngine = new ScopeEngine();
      const matrixEngine = new AuthorizationMatrixEngine(
        graph,
        () =>
          ({
            async request(input) {
              const client = new ScopedHttpClient(authorizationScopeEngine, scope, {
                beforeRequest: executionRequestGuard(
                  prisma,
                  scan.workspaceId,
                  scan.id,
                  "AUTHORIZATION",
                ),
                allowedMethods: [input.method],
                maxRequestBodyBytes: 256 * 1024,
              });
              const started = performance.now();
              const response = await client.request(input.url, {
                method: input.method,
                headers: input.headers,
                ...(input.body !== undefined ? { body: input.body } : {}),
                timeoutMs: input.timeoutMs,
                followRedirects: input.followRedirects,
                maxRedirects: 5,
                ...(input.signal ? { signal: input.signal } : {}),
              });
              return { response, durationMs: performance.now() - started };
            },
          }) satisfies AuthorizationTransport,
        {
          timeoutMs: scan.config.timeoutMs,
          globalConcurrency: Math.min(scan.config.concurrency, 8),
          perIdentityConcurrency: Math.min(scan.config.concurrency, 2),
          requestsPerSecond: Math.min(scan.config.requestsPerSecond, 10),
          maxRequests: Math.min(scan.config.maxRequests, 500),
        },
        (event) =>
          logger.info(event.type, { workspaceId: scan.workspaceId, scanId: scan.id, ...event }),
      );
      let candidateCount = 0;
      let cancelled = false;
      for (const persistedCase of scan.target.authorizationTestCases) {
        const cancellation = await prisma.scan.findUnique({
          where: { id: scan.id },
          select: { cancelRequestedAt: true },
        });
        if (cancellation?.cancelRequestedAt) {
          cancelled = true;
          break;
        }
        const testCase = testCaseValue(persistedCase, secretKey);
        try {
          const result = await matrixEngine.execute(testCase, prepared);
          const fingerprints: string[] = [];
          for (const difference of result.differences) {
            const candidate = observationForDifference(testCase, result, difference);
            if (!candidate) continue;
            const persisted = await evidence.record(scan.workspaceId, scan.id, candidate);
            fingerprints.push(persisted.signature);
            candidateCount += 1;
          }
          await prisma.authorizationTestResult.upsert({
            where: { scanId_testCaseId: { scanId: scan.id, testCaseId: testCase.id } },
            create: {
              workspaceId: scan.workspaceId,
              scanId: scan.id,
              testCaseId: testCase.id,
              correlationId: result.correlationId,
              matrix: jsonValue(result),
              findingFingerprints: fingerprints,
              incompleteIdentityIds: [...result.incompleteIdentityIds],
              degraded: result.incompleteIdentityIds.length > 0,
            },
            update: {
              correlationId: result.correlationId,
              matrix: jsonValue(result),
              findingFingerprints: fingerprints,
              incompleteIdentityIds: [...result.incompleteIdentityIds],
              degraded: result.incompleteIdentityIds.length > 0,
            },
          });
        } catch (error) {
          failures.push({
            identityId: `test-case:${testCase.id}`,
            reason: safeAuthenticationError(error),
          });
        }
      }
      for (const { context: requestContext } of prepared.values()) requestContext.dispose();

      if (cancelled) {
        await prisma.$transaction([
          prisma.scanJob.update({
            where: { id: String(job.id ?? "") },
            data: { status: JobStatus.CANCELLED, completedAt: new Date() },
          }),
          prisma.scanStage.update({
            where: { scanId_name: { scanId: scan.id, name: ScanState.AUTHORIZATION_ANALYSIS } },
            data: { status: StageStatus.CANCELLED, completedAt: new Date() },
          }),
          prisma.scan.update({
            where: { id: scan.id },
            data: { state: ScanState.CANCELLED, completedAt: new Date() },
          }),
          prisma.target.update({
            where: { id: scan.target.id },
            data: { status: TargetStatus.CANCELLED },
          }),
        ]);
        return { status: "CANCELLED", candidates: candidateCount };
      }

      const nextJob = await prisma.scanJob.upsert({
        where: { idempotencyKey: `${normalizeQueueName}:${scan.id}:v1` },
        create: {
          workspaceId: scan.workspaceId,
          scanId: scan.id,
          queue: normalizeQueueName,
          idempotencyKey: `${normalizeQueueName}:${scan.id}:v1`,
          status: JobStatus.CREATED,
          maxAttempts: 4,
          payload: jsonValue(job.data),
        },
        update: { payload: jsonValue(job.data) },
      });
      await prisma.$transaction([
        prisma.scanJob.update({
          where: { id: String(job.id ?? "") },
          data: {
            status: JobStatus.SUCCEEDED,
            completedAt: new Date(),
            result: jsonValue({
              testCases: scan.target.authorizationTestCases.length,
              candidates: candidateCount,
              failures,
            }),
          },
        }),
        prisma.scanStage.update({
          where: { scanId_name: { scanId: scan.id, name: ScanState.AUTHORIZATION_ANALYSIS } },
          data: {
            status: failures.length > 0 ? StageStatus.DEGRADED : StageStatus.COMPLETED,
            completedAt: new Date(),
            completedUnits: scan.target.authorizationTestCases.length,
            totalUnits: scan.target.authorizationTestCases.length,
            metadata: jsonValue({
              candidates: candidateCount,
              unavailableIdentities: failures.length,
            }),
          },
        }),
        prisma.scan.update({
          where: { id: scan.id },
          data: {
            state: ScanState.NORMALIZING,
            warningCount: { increment: failures.length > 0 ? 1 : 0 },
          },
        }),
      ]);
      try {
        await normalizeQueue.add(normalizeQueueName, job.data, {
          jobId: nextJob.id,
          attempts: nextJob.maxAttempts,
          backoff: { type: "exponential", delay: 2_000 },
        });
        await prisma.scanJob.update({
          where: { id: nextJob.id },
          data: { status: JobStatus.QUEUED, bullJobId: nextJob.id },
        });
      } catch (error) {
        logger.warn("authorization.normalize_handoff_deferred", {
          workspaceId: scan.workspaceId,
          scanId: scan.id,
          jobId: nextJob.id,
          reason: safeAuthenticationError(error),
        });
        // The durable CREATED job remains available to the existing outbox recovery loop.
      }
      return {
        testCases: scan.target.authorizationTestCases.length,
        candidates: candidateCount,
        failures: failures.length,
      };
    },
    { connection, concurrency: 1, lockDuration: 300_000 },
  );

  worker.on("failed", (job, error) => {
    if (!job) return;
    const safeError = safeAuthenticationError(error);
    void prisma
      .$transaction([
        prisma.scanJob.updateMany({
          where: { id: String(job.id) },
          data: { status: JobStatus.FAILED, completedAt: new Date(), lastError: safeError },
        }),
        prisma.scanStage.updateMany({
          where: { scanId: job.data.scanId, name: ScanState.AUTHORIZATION_ANALYSIS },
          data: { status: StageStatus.FAILED, completedAt: new Date(), errorMessage: safeError },
        }),
        prisma.scan.updateMany({
          where: { id: job.data.scanId, workspaceId: job.data.workspaceId },
          data: { state: ScanState.FAILED, failureReason: safeError },
        }),
      ])
      .catch(() => undefined);
  });

  return {
    async close() {
      await worker.close();
      await normalizeQueue.close();
      await connection.quit();
      await publisher.quit();
    },
  };
}
