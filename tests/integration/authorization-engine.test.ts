import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  AuthorizationMatrixEngine,
  IdentityRequestContext,
  ResourceOwnershipGraph,
  type AssessmentIdentity,
  type AuthorizationTestCase,
  type AuthorizationTransport,
  type PreparedIdentity,
} from "@aasp/authorization-engine";
import { ScopeEngine, ScopedHttpClient } from "@aasp/scope-engine";
import { createFixtureServer } from "../../fixtures/vulnerable-web/src/main.js";

const server = createFixtureServer();
let origin = "";

beforeAll(async () => {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as AddressInfo;
  origin = `http://127.0.0.1:${address.port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
});

function identity(id: string, role: string, tenant: string | null): AssessmentIdentity {
  return {
    id,
    label: id,
    role,
    tenant,
    authenticationType: id === "anonymous" ? "ANONYMOUS" : "CUSTOM_HEADERS",
    credentialReference: null,
    authenticationState: id === "anonymous" ? "UNKNOWN" : "AUTHENTICATED",
    metadata: {},
    enabled: true,
  };
}

function setup(resourceType = "order", externalId = "order-alice") {
  const identities = [
    identity("alice", "USER", "ACME"),
    identity("bob", "USER", "ACME"),
    identity("charlie", "USER", "GLOBEX"),
    identity("manager", "MANAGER", "ACME"),
    identity("admin", "ADMIN", "ACME"),
    identity("anonymous", "ANONYMOUS", null),
  ];
  const graph = new ResourceOwnershipGraph();
  for (const item of identities) graph.addIdentity(item);
  graph.addResource({
    id: "approved-resource",
    type: resourceType,
    externalId,
    tenant: "ACME",
    ownerIdentityId: resourceType === "admin-operation" ? "admin" : "alice",
    provenance: "APPROVED_SEED",
    endpointVariables: {},
    metadata: {},
  });
  const prepared = new Map<string, PreparedIdentity>();
  for (const item of identities) {
    const context = new IdentityRequestContext(item);
    context.applyCredential(
      item.authenticationType === "ANONYMOUS"
        ? { type: "ANONYMOUS" }
        : { type: "CUSTOM_HEADERS", headers: { "x-fixture-identity": item.id } },
    );
    prepared.set(item.id, { identity: item, context });
  }
  const policy = {
    targetOrigin: origin,
    allowedDomains: ["127.0.0.1"],
    includeSubdomains: false,
    allowPrivateNetwork: true,
    allowedPorts: [Number(new URL(origin).port)],
  };
  const engine = new AuthorizationMatrixEngine(
    graph,
    () =>
      ({
        async request(input) {
          const client = new ScopedHttpClient(new ScopeEngine(), policy, {
            allowedMethods: [input.method],
          });
          const started = performance.now();
          const response = await client.request(input.url, {
            method: input.method,
            headers: input.headers,
            followRedirects: input.followRedirects,
            timeoutMs: input.timeoutMs,
            ...(input.body !== undefined ? { body: input.body } : {}),
          });
          return { response, durationMs: performance.now() - started };
        },
      }) satisfies AuthorizationTransport,
    {
      timeoutMs: 5_000,
      globalConcurrency: 3,
      perIdentityConcurrency: 1,
      requestsPerSecond: 20,
      maxRequests: 30,
    },
  );
  return { engine, prepared };
}

function readCase(
  path: string,
  identityIds: string[],
  expectedPolicy: AuthorizationTestCase["expectedPolicy"],
): AuthorizationTestCase {
  return {
    id: `case-${path}`,
    name: path,
    resourceId: "approved-resource",
    action: "READ",
    endpointTemplate: `${origin}${path}`,
    method: "GET",
    identityIds,
    expectedPolicy,
    mutationRisk: "READ_ONLY",
    mutationExplicitlyAuthorized: false,
    cleanupStrategy: "NONE",
    requestHeaders: {},
    followRedirects: false,
    timingSamples: 1,
  };
}

describe("local multi-tenant authorization fixture", () => {
  it("does not flag correctly protected owner, non-owner, tenant, and anonymous boundaries", async () => {
    const { engine, prepared } = setup();
    const result = await engine.execute(
      readCase(
        "/api/authorization/orders/{resourceId}",
        ["alice", "bob", "charlie", "manager", "admin", "anonymous"],
        {
          alice: "ALLOW",
          bob: "DENY",
          charlie: "DENY",
          manager: "ALLOW",
          admin: "ALLOW",
          anonymous: "DENY",
        },
      ),
      prepared,
    );
    expect(
      result.differences.filter(
        ({ classification }) =>
          classification.startsWith("POTENTIAL_") ||
          classification === "AUTHENTICATION_INCONSISTENCY",
      ),
    ).toEqual([]);
    expect(
      result.observations.find(({ identityId }) => identityId === "bob")?.response.statusCode,
    ).toBe(403);
    expect(
      result.observations.find(({ identityId }) => identityId === "anonymous")?.response.statusCode,
    ).toBe(401);
  });

  it("detects horizontal and cross-tenant failures on the same approved resource", async () => {
    const { engine, prepared } = setup();
    const result = await engine.execute(
      readCase("/api/authorization/vulnerable/orders/{resourceId}", ["alice", "bob", "charlie"], {
        alice: "ALLOW",
        bob: "DENY",
        charlie: "DENY",
      }),
      prepared,
    );
    expect(result.differences.map(({ classification }) => classification).sort()).toEqual([
      "POTENTIAL_HORIZONTAL_BYPASS",
      "POTENTIAL_TENANT_BYPASS",
    ]);
    expect(
      result.differences.every(({ sensitiveFieldOverlap }) =>
        sensitiveFieldOverlap.includes("$.customer.email"),
      ),
    ).toBe(true);
  });

  it("detects a vertical role failure without mutating the fixture", async () => {
    const { engine, prepared } = setup("admin-operation", "audit");
    const result = await engine.execute(
      readCase("/api/authorization/vulnerable/admin/{resourceId}", ["admin", "alice"], {
        admin: "ALLOW",
        alice: "DENY",
      }),
      prepared,
    );
    expect(result.differences[0]?.classification).toBe("POTENTIAL_VERTICAL_BYPASS");
    expect(result.differences[0]?.severity).toBe("HIGH");
  });

  it("blocks out-of-scope redirects before contacting the destination", async () => {
    const policy = {
      targetOrigin: origin,
      allowedDomains: ["127.0.0.1"],
      includeSubdomains: false,
      allowPrivateNetwork: true,
      allowedPorts: [Number(new URL(origin).port)],
    };
    const client = new ScopedHttpClient(new ScopeEngine(), policy);
    await expect(
      client.request(`${origin}/redirect?next=https://outside.example.invalid/`, {
        followRedirects: true,
      }),
    ).rejects.toMatchObject({ reason: "HOST_NOT_AUTHORIZED" });
  });

  it("keeps unsafe methods disabled unless the client and disposable test explicitly authorize them", async () => {
    const policy = {
      targetOrigin: origin,
      allowedDomains: ["127.0.0.1"],
      includeSubdomains: false,
      allowPrivateNetwork: true,
      allowedPorts: [Number(new URL(origin).port)],
    };
    await expect(
      new ScopedHttpClient(new ScopeEngine(), policy).request(`${origin}/health`, {
        method: "DELETE",
      }),
    ).rejects.toMatchObject({ reason: "UNSAFE_METHOD" });
    const { engine, prepared } = setup();
    const unsafe = {
      ...readCase("/api/authorization/orders/{resourceId}", ["alice", "bob"], {
        alice: "ALLOW",
        bob: "DENY",
      }),
      method: "DELETE" as const,
    };
    await expect(engine.execute(unsafe, prepared)).rejects.toThrow(
      /disposable-fixture authorization/u,
    );
  });
});
