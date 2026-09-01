import { describe, expect, it } from "vitest";
import { AuthenticationSurfaceScanner } from "@aasp/scanner-auth-surface";
import { CookieSecurityScanner, parseSetCookie } from "@aasp/scanner-cookies";
import { analyzeCors } from "@aasp/scanner-cors";
import { HeaderSecurityScanner } from "@aasp/scanner-headers";
import { HttpSecurityScanner } from "@aasp/scanner-http";
import type { HttpExchange } from "@aasp/scanner-integrations";
import { MisconfigurationScanner } from "@aasp/scanner-misconfiguration";
import type { ScopedHttpClient, ScopedResponse } from "@aasp/scope-engine";

function exchange(overrides: Partial<HttpExchange> = {}): HttpExchange {
  return {
    requestedUrl: "https://fixture.test/login",
    finalUrl: "https://fixture.test/login",
    method: "GET",
    statusCode: 200,
    headers: { "content-type": "text/html", "x-powered-by": "Fixture/1.0" },
    body: "<h1>Login</h1>",
    redirects: [],
    ...overrides,
  };
}

describe("Day 3 deterministic scanners", () => {
  it("profiles HTTP and records explicit disclosure", () => {
    const types = new HttpSecurityScanner()
      .analyze([exchange()])
      .map((item) => item.observationType);
    expect(types).toContain("HTTP_RESPONSE_PROFILE");
    expect(types).toContain("SERVER_TECHNOLOGY_DISCLOSURE");
  });

  it("uses contextual low/info severities for missing HTML headers", () => {
    const results = new HeaderSecurityScanner().analyze([exchange()]);
    expect(
      results.find((item) => item.observationType === "CONTENT_SECURITY_POLICY_MISSING")
        ?.rawSeverity,
    ).toBe("LOW");
    expect(
      results.find((item) => item.observationType === "REFERRER_POLICY_MISSING")?.rawSeverity,
    ).toBe("INFO");
    expect(results.some((item) => item.rawSeverity === "CRITICAL")).toBe(false);
  });

  it("does not apply HTML header rules to JSON responses", () => {
    expect(
      new HeaderSecurityScanner().analyze([
        exchange({ headers: { "content-type": "application/json" } }),
      ]),
    ).toHaveLength(0);
  });

  it("parses cookie attributes without retaining its secret value", () => {
    expect(parseSetCookie("sid=super-secret; Path=/; HttpOnly; SameSite=Lax")).toEqual({
      name: "sid",
      secure: false,
      httpOnly: true,
      sameSite: "Lax",
      domain: null,
      path: "/",
      expires: null,
    });
  });

  it("flags missing session-cookie protections with redacted evidence", () => {
    const results = new CookieSecurityScanner().analyze([
      exchange({ headers: { "set-cookie": "fixture_session=super-secret; Path=/" } }),
    ]);
    expect(results.map((item) => item.observationType)).toEqual([
      "COOKIE_SECURE_ATTRIBUTE_MISSING",
      "SESSION_COOKIE_HTTPONLY_MISSING",
      "COOKIE_SAMESITE_WEAK_OR_MISSING",
    ]);
    expect(JSON.stringify(results)).not.toContain("super-secret");
  });

  it("discovers authentication surfaces without credential attempts", () => {
    const result = new AuthenticationSurfaceScanner().analyze([exchange()]);
    expect(result).toHaveLength(1);
    expect(result[0]?.metadata).toMatchObject({ surfaceType: "LOGIN_OR_SESSION" });
  });

  it("requires response evidence for verbose errors and source maps", () => {
    const results = new MisconfigurationScanner().analyze([
      exchange({
        finalUrl: "https://fixture.test/error",
        statusCode: 500,
        body: "Error: failed\n at route (/srv/app.ts:1:1)",
      }),
      exchange({ finalUrl: "https://fixture.test/app.js.map", body: '{"sources":["src/app.ts"]}' }),
    ]);
    expect(results.map((item) => item.observationType)).toEqual([
      "VERBOSE_ERROR_DETAILS_OBSERVED",
      "SOURCE_MAP_PUBLICLY_ACCESSIBLE",
    ]);
  });

  it("classifies reflected origins with credentials from a controlled request", async () => {
    const calls: Array<{ url: string; method: string | undefined }> = [];
    const client = {
      request(
        url: string,
        options: { method?: "GET" | "HEAD" | "OPTIONS" },
      ): Promise<ScopedResponse> {
        calls.push({ url, method: options.method });
        return Promise.resolve({
          requestedUrl: url,
          finalUrl: url,
          statusCode: 200,
          headers: {
            "access-control-allow-origin": "https://aasp-invalid-origin.invalid",
            "access-control-allow-credentials": "true",
          },
          body: Buffer.from("{}"),
          redirects: [],
        });
      },
    } as ScopedHttpClient;
    const result = await analyzeCors(client, ["https://fixture.test/cors"], {
      timeoutMs: 1_000,
      maxRequests: 1,
      requestsPerSecond: 10,
    });
    expect(calls).toEqual([{ url: "https://fixture.test/cors", method: "GET" }]);
    expect(result.observations[0]?.observationType).toBe("CORS_ARBITRARY_ORIGIN_WITH_CREDENTIALS");
  });
});
