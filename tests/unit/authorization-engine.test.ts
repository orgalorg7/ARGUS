import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  BrowserContextManager,
  IdentityRequestContext,
  ResourceOwnershipGraph,
  authorizationFindingFingerprint,
  compareAuthorizationResponses,
  decryptCredential,
  encryptCredential,
  normalizeResponse,
  testLogoutInvalidation,
  testSessionRotation,
  type AssessmentIdentity,
} from "@aasp/authorization-engine";

function identity(
  id: string,
  authenticationType: AssessmentIdentity["authenticationType"] = "CUSTOM_HEADERS",
  role = "USER",
  tenant: string | null = "ACME",
): AssessmentIdentity {
  return {
    id,
    label: id,
    role,
    tenant,
    authenticationType,
    credentialReference: null,
    authenticationState: authenticationType === "ANONYMOUS" ? "UNKNOWN" : "AUTHENTICATED",
    metadata: {},
    enabled: true,
  };
}

describe("multi-identity authorization engine", () => {
  it("isolates cookies, headers, CSRF state, and anonymous state", () => {
    const alice = new IdentityRequestContext(identity("alice"));
    const bob = new IdentityRequestContext(identity("bob"));
    alice.applyCredential({
      type: "CUSTOM_HEADERS",
      headers: { authorization: "Bearer alice-value" },
    });
    bob.applyCredential({ type: "CUSTOM_HEADERS", headers: { authorization: "Bearer bob-value" } });
    alice.cookieJar.setCookie("session=alice-cookie; Path=/", "https://app.example.test/orders");
    bob.cookieJar.setCookie("session=bob-cookie; Path=/", "https://app.example.test/orders");
    alice.setCsrf("default", "alice-csrf");
    bob.setCsrf("default", "bob-csrf");

    expect(alice.requestHeaders("https://app.example.test/orders")).toEqual({
      authorization: "Bearer alice-value",
      cookie: "session=alice-cookie",
    });
    expect(bob.requestHeaders("https://app.example.test/orders")).toEqual({
      authorization: "Bearer bob-value",
      cookie: "session=bob-cookie",
    });
    expect(alice.getCsrf("default")).toBe("alice-csrf");
    expect(bob.getCsrf("default")).toBe("bob-csrf");

    const anonymous = new IdentityRequestContext(
      identity("anonymous", "ANONYMOUS", "ANONYMOUS", null),
    );
    anonymous.applyCredential({ type: "ANONYMOUS" });
    expect(anonymous.requestHeaders("https://app.example.test/orders")).toEqual({});
    expect(() => anonymous.setHeader("authorization", "Bearer leaked-admin-value")).not.toThrow();
    expect(() => anonymous.assertAnonymous()).toThrow(/authentication header/u);
  });

  it("normalizes volatile JSON, detects structure and sensitive paths without retaining values", () => {
    const left = normalizeResponse({
      statusCode: 200,
      headers: { "content-type": "application/json" },
      body: Buffer.from(
        JSON.stringify({
          id: "one",
          requestId: "volatile-one",
          customer: { email: "alice@example.invalid" },
          payment: { last4: "0000" },
        }),
      ),
      redirects: [],
      durationMs: 20,
    });
    const right = normalizeResponse({
      statusCode: 200,
      headers: { "content-type": "application/json" },
      body: Buffer.from(
        JSON.stringify({
          id: "two",
          requestId: "volatile-two",
          customer: { email: "bob@example.invalid" },
          payment: { last4: "9999" },
        }),
      ),
      redirects: [],
      durationMs: 24,
    });
    expect(left.jsonFieldPaths).toContain("$.customer.email");
    expect(left.sensitiveFieldPaths).toEqual(["$.customer.email", "$.payment", "$.payment.last4"]);
    expect(left.redactedExcerpt).not.toContain("alice@example.invalid");
    const difference = compareAuthorizationResponses({
      baseline: {
        identityId: "alice",
        identityLabel: "Alice",
        identityRole: "USER",
        identityTenant: "ACME",
        authenticationState: "AUTHENTICATED",
        expected: "ALLOW",
        requestedUrl: "https://app.example.test/orders/one",
        response: left,
        evidenceFingerprint: "a",
        error: null,
      },
      comparison: {
        identityId: "bob",
        identityLabel: "Bob",
        identityRole: "USER",
        identityTenant: "ACME",
        authenticationState: "AUTHENTICATED",
        expected: "DENY",
        requestedUrl: "https://app.example.test/orders/one",
        response: right,
        evidenceFingerprint: "b",
        error: null,
      },
      relationship: "SAME_ROLE_NON_OWNER",
      reproducible: true,
    });
    expect(difference.classification).toBe("POTENTIAL_HORIZONTAL_BYPASS");
    expect(difference.structuralSimilarity).toBe(1);
    expect(difference.confidence).toBeGreaterThanOrEqual(0.9);
    expect(difference.severity).toBe("HIGH");
  });

  it("models owner, role, and tenant relationships intentionally", () => {
    const graph = new ResourceOwnershipGraph();
    for (const item of [
      identity("alice"),
      identity("bob"),
      identity("charlie", "CUSTOM_HEADERS", "USER", "GLOBEX"),
      identity("admin", "CUSTOM_HEADERS", "ADMIN"),
    ])
      graph.addIdentity(item);
    graph.addResource({
      id: "resource-one",
      type: "order",
      externalId: "order-one",
      tenant: "ACME",
      ownerIdentityId: "alice",
      provenance: "OPERATOR_SUPPLIED",
      endpointVariables: {},
      metadata: {},
    });
    expect(graph.relationships("alice", "resource-one").has("OWNS")).toBe(true);
    expect(
      graph.comparisonRelationship(
        graph.identity("alice"),
        graph.identity("bob"),
        graph.resource("resource-one"),
      ),
    ).toBe("SAME_ROLE_NON_OWNER");
    expect(
      graph.comparisonRelationship(
        graph.identity("alice"),
        graph.identity("charlie"),
        graph.resource("resource-one"),
      ),
    ).toBe("CROSS_TENANT");
    expect(
      graph.comparisonRelationship(
        graph.identity("admin"),
        graph.identity("bob"),
        graph.resource("resource-one"),
      ),
    ).toBe("LOWER_ROLE");
  });

  it("encrypts credentials with authenticated encryption and stores no plaintext", () => {
    const key = randomBytes(32).toString("base64");
    const material = { type: "BEARER_TOKEN" as const, token: "unit-test-sensitive-value" };
    const encrypted = encryptCredential(material, key);
    expect(JSON.stringify(encrypted)).not.toContain(material.token);
    expect(decryptCredential(encrypted, key)).toEqual(material);
    expect(() =>
      decryptCredential(
        { ...encrypted, ciphertext: `${encrypted.ciphertext.slice(0, -2)}AA` },
        key,
      ),
    ).toThrow();
  });

  it("guarantees one browser context instance per identity and deterministic cleanup", async () => {
    let closed = 0;
    const manager = new BrowserContextManager({
      createContext({ identityId }) {
        return Promise.resolve({
          identityId,
          close() {
            closed += 1;
            return Promise.resolve();
          },
        });
      },
    });
    const aliceContext = await manager.create(identity("alice"), {
      sessionFingerprint: "alice-hash",
    });
    const bobContext = await manager.create(identity("bob"), { sessionFingerprint: "bob-hash" });
    expect(aliceContext).not.toBe(bobContext);
    await manager.closeAll();
    expect(closed).toBe(2);

    const shared = {
      close() {
        closed += 1;
        return Promise.resolve();
      },
    };
    const broken = new BrowserContextManager({
      createContext() {
        return Promise.resolve(shared);
      },
    });
    await broken.create(identity("alice"), { sessionFingerprint: "alice-hash" });
    await expect(
      broken.create(identity("bob"), { sessionFingerprint: "bob-hash" }),
    ).rejects.toThrow(/reused/u);
  });

  it("rejects authenticated bootstrap for an anonymous browser context", async () => {
    const manager = new BrowserContextManager({
      createContext() {
        return Promise.resolve({ close: () => Promise.resolve() });
      },
    });
    await expect(
      manager.create(identity("anonymous", "ANONYMOUS", "ANONYMOUS", null), {
        sessionFingerprint: "residual-admin-state",
      }),
    ).rejects.toThrow(/Anonymous browser bootstrap/u);
  });

  it("records only session fingerprints for rotation and bounded logout replay", async () => {
    let current = "session-one";
    const source = { sessionFingerprint: () => current };
    const rotation = await testSessionRotation({
      context: source,
      securityRelevantTransition() {
        current = "session-two";
        return Promise.resolve();
      },
    });
    expect(rotation.rotated).toBe(true);
    const logout = await testLogoutInvalidation({
      context: source,
      authorizedRequest() {
        return Promise.resolve(200);
      },
      logout() {
        return Promise.resolve(204);
      },
      replayPreviousSessionRequest() {
        return Promise.resolve(401);
      },
    });
    expect(logout.previousSessionStillUsable).toBe(false);
    expect(logout.sessionFingerprint).not.toBe(current);
  });

  it("deduplicates equivalent authorization boundaries without resource IDs", () => {
    const first = authorizationFindingFingerprint({
      endpointTemplate: "https://app.example.test/api/orders/{resourceId}",
      method: "GET",
      resourceType: "order",
      classification: "POTENTIAL_HORIZONTAL_BYPASS",
      relationship: "SAME_ROLE_NON_OWNER",
      tenantRelationship: "SAME_TENANT",
    });
    const second = authorizationFindingFingerprint({
      endpointTemplate: "https://app.example.test/api/orders/{resourceId}",
      method: "GET",
      resourceType: "order",
      classification: "POTENTIAL_HORIZONTAL_BYPASS",
      relationship: "SAME_ROLE_NON_OWNER",
      tenantRelationship: "SAME_TENANT",
    });
    expect(first).toBe(second);
    expect(first).toMatch(/^[a-f0-9]{64}$/u);
  });
});
