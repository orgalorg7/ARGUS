import { createHash, randomUUID } from "node:crypto";
import { evidenceHash, redactHeaders } from "@aasp/security-core";
import type { IdentityRequestContext } from "./identity-context.js";
import type { ResourceOwnershipGraph } from "./ownership-graph.js";
import {
  authenticationStateAfterResponse,
  compareAuthorizationResponses,
  normalizeResponse,
} from "./response-analysis.js";
import type {
  AssessmentIdentity,
  AuthorizationMatrixResult,
  AuthorizationObservation,
  AuthorizationTestCase,
  AuthorizationTransport,
  AuthorizedResource,
} from "./types.js";

const safeMethods = new Set(["GET", "HEAD", "OPTIONS"]);
const approvedProvenance = new Set([
  "OPERATOR_SUPPLIED",
  "SCANNER_CREATED",
  "APPROVED_SEED",
  "IDENTITY_OBSERVED",
]);

export interface AuthorizationEngineLimits {
  timeoutMs: number;
  globalConcurrency: number;
  perIdentityConcurrency: number;
  requestsPerSecond: number;
  maxRequests: number;
}

export interface AuthorizationEngineEvent {
  type:
    | "identity.created"
    | "identity.authenticated"
    | "identity.authentication_failed"
    | "authorization_test.started"
    | "authorization_test.completed"
    | "authorization_difference.detected"
    | "finding.created";
  correlationId: string;
  identityId?: string;
  testCaseId?: string;
  safeMetadata?: Readonly<Record<string, unknown>>;
}

export interface PreparedIdentity {
  identity: AssessmentIdentity;
  context: IdentityRequestContext;
}

export type AuthorizationCleanupHandler = (input: {
  testCase: AuthorizationTestCase;
  resource: AuthorizedResource;
  identity: AssessmentIdentity;
  correlationId: string;
}) => Promise<void>;

class Semaphore {
  #active = 0;
  readonly #waiting: Array<() => void> = [];
  constructor(private readonly limit: number) {
    if (!Number.isInteger(limit) || limit < 1)
      throw new Error("Concurrency limit must be positive.");
  }
  async run<T>(task: () => Promise<T>): Promise<T> {
    if (this.#active >= this.limit)
      await new Promise<void>((resolve) => this.#waiting.push(resolve));
    this.#active += 1;
    try {
      return await task();
    } finally {
      this.#active -= 1;
      this.#waiting.shift()?.();
    }
  }
}

class RateGate {
  #next = 0;
  constructor(requestsPerSecond: number) {
    if (!(requestsPerSecond > 0 && requestsPerSecond <= 20)) {
      throw new Error("Authorization request rate must be between 0 and 20 requests/second.");
    }
    this.intervalMs = 1_000 / requestsPerSecond;
  }
  private readonly intervalMs: number;
  async wait(): Promise<void> {
    const now = Date.now();
    const scheduled = Math.max(now, this.#next);
    this.#next = scheduled + this.intervalMs;
    const delay = scheduled - now;
    if (delay > 0) await new Promise((resolve) => setTimeout(resolve, delay));
  }
}

function renderEndpoint(testCase: AuthorizationTestCase, resource: AuthorizedResource): string {
  const variables: Readonly<Record<string, string>> = {
    resourceId: resource.externalId,
    ...resource.endpointVariables,
  };
  const rendered = testCase.endpointTemplate.replace(
    /\{([A-Za-z][A-Za-z0-9_]*)\}/gu,
    (_, key: string) => {
      const value = variables[key];
      if (value === undefined)
        throw new Error(`Endpoint variable ${key} is not defined by the approved resource.`);
      return encodeURIComponent(value);
    },
  );
  if (/\{[^}]+\}/u.test(rendered)) throw new Error("Endpoint contains unresolved variables.");
  return new URL(rendered).toString();
}

export class AuthorizationMatrixEngine {
  readonly #global: Semaphore;
  readonly #identityLimits = new Map<string, Semaphore>();
  readonly #rateGate: RateGate;
  #requestCount = 0;

  constructor(
    private readonly graph: ResourceOwnershipGraph,
    private readonly transportFor: (identity: AssessmentIdentity) => AuthorizationTransport,
    private readonly limits: AuthorizationEngineLimits,
    private readonly emit: (event: AuthorizationEngineEvent) => void = () => undefined,
    private readonly cleanupHandler?: AuthorizationCleanupHandler,
  ) {
    this.#global = new Semaphore(limits.globalConcurrency);
    this.#rateGate = new RateGate(limits.requestsPerSecond);
  }

  async execute(
    testCase: AuthorizationTestCase,
    preparedIdentities: ReadonlyMap<string, PreparedIdentity>,
    signal?: AbortSignal,
  ): Promise<AuthorizationMatrixResult> {
    const correlationId = randomUUID();
    const startedAt = new Date().toISOString();
    const resource = this.graph.resource(testCase.resourceId);
    this.assertTestCaseAllowed(testCase, resource);
    this.emit({ type: "authorization_test.started", correlationId, testCaseId: testCase.id });

    const observations = (
      await Promise.all(
        testCase.identityIds.map(async (identityId) => {
          const prepared = preparedIdentities.get(identityId);
          if (!prepared || !prepared.identity.enabled) return null;
          if (
            ["AUTH_FAILED", "UNAVAILABLE", "AUTH_EXPIRED", "LOGGED_OUT"].includes(
              prepared.identity.authenticationState,
            )
          ) {
            return null;
          }
          return this.#global.run(() =>
            this.identitySemaphore(identityId).run(() =>
              this.observe(testCase, resource, prepared, correlationId, signal),
            ),
          );
        }),
      )
    ).filter((item): item is AuthorizationObservation => item !== null);

    const baseline =
      observations.find((item) =>
        this.graph.relationships(item.identityId, resource.id).has("OWNS"),
      ) ?? observations.find((item) => item.expected === "ALLOW");
    const differences = baseline
      ? observations
          .filter((item) => item.identityId !== baseline.identityId)
          .map((comparison) => {
            const difference = compareAuthorizationResponses({
              baseline,
              comparison,
              relationship: this.graph.comparisonRelationship(
                this.graph.identity(baseline.identityId),
                this.graph.identity(comparison.identityId),
                resource,
              ),
              reproducible: baseline.reproducible === true && comparison.reproducible === true,
            });
            if (
              difference.classification.startsWith("POTENTIAL_") ||
              difference.classification === "AUTHENTICATION_INCONSISTENCY"
            ) {
              this.emit({
                type: "authorization_difference.detected",
                correlationId,
                testCaseId: testCase.id,
                identityId: comparison.identityId,
                safeMetadata: {
                  classification: difference.classification,
                  confidence: difference.confidence,
                },
              });
            }
            return difference;
          })
      : [];
    const observedIds = new Set(observations.map((item) => item.identityId));
    const result: AuthorizationMatrixResult = {
      testCaseId: testCase.id,
      correlationId,
      resource,
      observations,
      differences,
      incompleteIdentityIds: testCase.identityIds.filter((id) => !observedIds.has(id)),
      startedAt,
      completedAt: new Date().toISOString(),
    };
    this.emit({
      type: "authorization_test.completed",
      correlationId,
      testCaseId: testCase.id,
      safeMetadata: {
        completedIdentities: observations.length,
        incompleteIdentities: result.incompleteIdentityIds.length,
      },
    });
    return result;
  }

  private async observe(
    testCase: AuthorizationTestCase,
    resource: AuthorizedResource,
    prepared: PreparedIdentity,
    correlationId: string,
    signal?: AbortSignal,
  ): Promise<AuthorizationObservation> {
    const url = renderEndpoint(testCase, resource);
    const headers = prepared.context.requestHeaders(url, {
      ...testCase.requestHeaders,
      ...(testCase.contentType ? { "content-type": testCase.contentType } : {}),
      "x-aasp-correlation-id": correlationId,
    });
    const samples = [];
    for (let index = 0; index < testCase.timingSamples; index += 1) {
      if (signal?.aborted) throw signal.reason ?? new Error("Authorization test cancelled.");
      if (this.#requestCount >= this.limits.maxRequests)
        throw new Error("Authorization request budget exhausted.");
      this.#requestCount += 1;
      await this.#rateGate.wait();
      const transport = this.transportFor(prepared.identity);
      const result = await transport.request({
        url,
        method: testCase.method,
        headers,
        ...(testCase.requestBody !== undefined ? { body: testCase.requestBody } : {}),
        timeoutMs: this.limits.timeoutMs,
        followRedirects: testCase.followRedirects,
        ...(signal ? { signal } : {}),
      });
      prepared.context.ingestResponse(result.response.headers, result.response.finalUrl);
      if (prepared.identity.authenticationType === "ANONYMOUS") prepared.context.assertAnonymous();
      samples.push(
        normalizeResponse({
          statusCode: result.response.statusCode,
          headers: result.response.headers,
          body: result.response.body,
          redirects: result.response.redirects,
          durationMs: result.durationMs,
        }),
      );
    }
    const response = samples[0];
    if (!response) throw new Error("Authorization test produced no response sample.");
    const orderedTimings = samples
      .map(({ timingMs }) => timingMs)
      .sort((left, right) => left - right);
    const medianTiming = orderedTimings[Math.floor(orderedTimings.length / 2)] ?? response.timingMs;
    const normalizedResponse = { ...response, timingMs: medianTiming };
    const reproducible = samples.every(
      (sample) =>
        sample.statusCode === response.statusCode &&
        sample.normalizedBodyHash === response.normalizedBodyHash &&
        sample.redirectLocation === response.redirectLocation,
    );
    if (!safeMethods.has(testCase.method)) {
      await this.cleanupHandler?.({
        testCase,
        resource,
        identity: prepared.identity,
        correlationId,
      });
    }
    return {
      identityId: prepared.identity.id,
      identityLabel: prepared.identity.label,
      identityRole: prepared.identity.role,
      identityTenant: prepared.identity.tenant,
      authenticationState: authenticationStateAfterResponse(
        prepared.identity.authenticationState,
        normalizedResponse.statusCode,
      ),
      expected: testCase.expectedPolicy[prepared.identity.id] ?? "UNKNOWN",
      requestedUrl: url,
      response: normalizedResponse,
      evidenceFingerprint: evidenceHash({
        testCaseId: testCase.id,
        identityId: prepared.identity.id,
        request: { url, method: testCase.method, headers: redactHeaders(headers) },
        response: {
          statusCode: normalizedResponse.statusCode,
          normalizedBodyHash: normalizedResponse.normalizedBodyHash,
          jsonFieldPaths: normalizedResponse.jsonFieldPaths,
        },
      }),
      error: null,
      reproducible,
    };
  }

  private identitySemaphore(identityId: string): Semaphore {
    const existing = this.#identityLimits.get(identityId);
    if (existing) return existing;
    const semaphore = new Semaphore(this.limits.perIdentityConcurrency);
    this.#identityLimits.set(identityId, semaphore);
    return semaphore;
  }

  private assertTestCaseAllowed(
    testCase: AuthorizationTestCase,
    resource: AuthorizedResource,
  ): void {
    if (!approvedProvenance.has(resource.provenance))
      throw new Error("Resource provenance is not approved.");
    if (testCase.identityIds.length < 2)
      throw new Error("Authorization comparison requires at least two identities.");
    if (new Set(testCase.identityIds).size !== testCase.identityIds.length)
      throw new Error("Test case contains duplicate identities.");
    for (const identityId of testCase.identityIds) this.graph.identity(identityId);
    if (!safeMethods.has(testCase.method)) {
      if (
        !testCase.mutationExplicitlyAuthorized ||
        testCase.mutationRisk !== "DISPOSABLE_TEST_FIXTURE" ||
        testCase.cleanupStrategy === "NONE" ||
        !this.cleanupHandler
      ) {
        throw new Error(
          "State-changing authorization tests require explicit disposable-fixture authorization and an active cleanup adapter.",
        );
      }
    }
    if (testCase.timingSamples < 1 || testCase.timingSamples > 5) {
      throw new Error("Timing samples must remain between 1 and 5.");
    }
    if (!safeMethods.has(testCase.method) && testCase.timingSamples !== 1) {
      throw new Error("State-changing authorization tests cannot enable repeated timing samples.");
    }
  }
}

export function authorizationFindingFingerprint(input: {
  endpointTemplate: string;
  method: string;
  resourceType: string;
  classification: string;
  relationship: string;
  tenantRelationship: string;
}): string {
  return createHash("sha256")
    .update(
      [
        input.method.toUpperCase(),
        input.endpointTemplate,
        input.resourceType,
        input.classification,
        input.relationship,
        input.tenantRelationship,
      ].join("\u0000"),
    )
    .digest("hex");
}
