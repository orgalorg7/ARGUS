import { describe, expect, it, vi } from "vitest";
import {
  IdentityRequestContext,
  normalizeResponse,
  safeAuthenticationError,
  type AssessmentIdentity,
} from "@aasp/authorization-engine";
import { logger } from "@aasp/logger";
import { redactUnknown } from "@aasp/security-core";

function identity(id: string, type: AssessmentIdentity["authenticationType"]): AssessmentIdentity {
  return {
    id,
    label: id,
    role: id === "admin" ? "ADMIN" : "USER",
    tenant: "ACME",
    authenticationType: type,
    credentialReference: null,
    authenticationState: type === "ANONYMOUS" ? "UNKNOWN" : "AUTHENTICATED",
    metadata: {},
    enabled: true,
  };
}

describe("authorization security regressions", () => {
  it("never lets admin headers enter a user or anonymous request context", () => {
    const admin = new IdentityRequestContext(identity("admin", "BEARER_TOKEN"));
    admin.applyCredential({ type: "BEARER_TOKEN", token: "admin-sensitive-value" });
    const user = new IdentityRequestContext(identity("alice", "BEARER_TOKEN"));
    user.applyCredential({ type: "BEARER_TOKEN", token: "alice-sensitive-value" });
    const anonymous = new IdentityRequestContext(identity("anonymous", "ANONYMOUS"));
    anonymous.applyCredential({ type: "ANONYMOUS" });
    expect(user.requestHeaders("https://app.example.test")["authorization"]).not.toBe(
      admin.requestHeaders("https://app.example.test")["authorization"],
    );
    expect(anonymous.requestHeaders("https://app.example.test")).toEqual({});
  });

  it("redacts secrets and PII from structured evidence and errors", () => {
    const source = {
      authorization: "Bearer report-sensitive-value",
      cookie: "session=report-sensitive-cookie",
      customer: { email: "person@example.invalid", address: "private address" },
    };
    const serialized = JSON.stringify(redactUnknown(source));
    expect(serialized).not.toContain("report-sensitive-value");
    expect(serialized).not.toContain("person@example.invalid");
    expect(safeAuthenticationError(new Error("Bearer report-sensitive-value"))).not.toContain(
      "report-sensitive-value",
    );
    const response = normalizeResponse({
      statusCode: 200,
      headers: { "content-type": "application/json", "set-cookie": "session=secret" },
      body: Buffer.from(JSON.stringify(source)),
      redirects: [],
      durationMs: 1,
    });
    expect(response.redactedExcerpt).not.toContain("person@example.invalid");
    expect(JSON.stringify(response.selectedHeaders)).not.toContain("session=secret");
  });

  it("redacts configured secrets from structured logger output", () => {
    const writes: string[] = [];
    const spy = vi.spyOn(process.stdout, "write").mockImplementation((chunk) => {
      writes.push(String(chunk));
      return true;
    });
    try {
      logger.info("identity.authentication_failed", {
        authorization: "Bearer logger-sensitive-value",
        nested: { password: "logger-sensitive-password" },
      });
    } finally {
      spy.mockRestore();
    }
    const output = writes.join("");
    expect(output).not.toContain("logger-sensitive-value");
    expect(output).not.toContain("logger-sensitive-password");
    expect(output).toContain("[REDACTED]");
  });

  it("cleans all in-memory authentication material on scanner shutdown", () => {
    const context = new IdentityRequestContext(identity("alice", "SESSION_COOKIE"));
    context.applyCredential({
      type: "SESSION_COOKIE",
      name: "session",
      value: "ephemeral-value",
      domain: "app.example.test",
    });
    expect(context.sessionFingerprint()).not.toBeNull();
    context.dispose();
    expect(context.sessionFingerprint()).toBeNull();
    expect(context.requestHeaders("https://app.example.test")).toEqual({});
  });
});
