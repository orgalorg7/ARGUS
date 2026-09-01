import { describe, expect, it } from "vitest";
import {
  evidenceHash,
  redactHeaders,
  redactText,
  redactUnknown,
  sanitizeTextForPersistence,
} from "@aasp/security-core";

describe("evidence redaction", () => {
  it("redacts credential-bearing request and response headers", () => {
    expect(
      redactHeaders({
        Authorization: "Bearer secret",
        Cookie: "sid=secret",
        "Content-Type": "text/html",
      }),
    ).toEqual({ Authorization: "[REDACTED]", Cookie: "[REDACTED]", "Content-Type": "text/html" });
  });

  it("redacts Set-Cookie values when nested in response metadata", () => {
    expect(redactUnknown({ headers: { "set-cookie": "session=secret; Path=/" } })).toEqual({
      headers: { "set-cookie": "[REDACTED]" },
    });
  });

  it("preserves non-secret CORS credential-policy booleans", () => {
    expect(
      redactUnknown({ accessControlAllowCredentials: "true", allowCredentials: true }),
    ).toEqual({ accessControlAllowCredentials: "true", allowCredentials: true });
  });

  it("redacts bearer values, JWT-like values, and nested secret fields", () => {
    expect(redactText("Authorization: Bearer abc.def password=hunter2")).not.toContain("hunter2");
    expect(redactUnknown({ profile: { apiKey: "secret", displayName: "Analyst" } })).toEqual({
      profile: { apiKey: "[REDACTED]", displayName: "Analyst" },
    });
  });

  it("removes PostgreSQL-incompatible and terminal control characters", () => {
    expect(sanitizeTextForPersistence("before\u0000after\u0007\nkept\tstructure")).toBe(
      "beforeafter\nkept\tstructure",
    );
    expect(redactUnknown({ excerpt: "safe\u0000text" })).toEqual({ excerpt: "safetext" });
  });

  it("produces stable SHA-256 evidence hashes", () => {
    expect(evidenceHash("same evidence")).toBe(evidenceHash("same evidence"));
    expect(evidenceHash("same evidence")).toMatch(/^[a-f0-9]{64}$/);
  });
});
