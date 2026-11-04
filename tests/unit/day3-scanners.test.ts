import { describe, expect, it } from "vitest";
import { analyzeSafeApplicationInputs, ApplicationSurfaceScanner } from "@aasp/scanner-application";
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

  it("records forms and conservatively flags missing observable CSRF fields", () => {
    const results = new ApplicationSurfaceScanner().analyze([
      exchange({
        body: '<form method="post" action="/account/email"><input name="email"></form>',
      }),
    ]);
    expect(results.map((item) => item.observationType)).toEqual([
      "FORM_INPUT_SURFACE_OBSERVED",
      "FORM_CSRF_PROTECTION_NOT_OBSERVED",
    ]);
    expect(results[1]?.metadata).toMatchObject({ formMethod: "POST" });
  });

  it("does not flag a form with an observable anti-CSRF field", () => {
    const results = new ApplicationSurfaceScanner().analyze([
      exchange({
        body: '<form method="post"><input type="hidden" name="csrf_token"><input name="email"></form>',
      }),
    ]);
    expect(results.map((item) => item.observationType)).toEqual(["FORM_INPUT_SURFACE_OBSERVED"]);
  });

  it("classifies client sinks without claiming executable data flow", () => {
    const results = new ApplicationSurfaceScanner().analyze([
      exchange({
        finalUrl: "https://fixture.test/assets/app.js",
        headers: { "content-type": "application/javascript" },
        body: 'element.innerHTML = value; const socket = "wss://fixture.test/events";',
      }),
    ]);
    expect(results.map((item) => item.observationType)).toEqual([
      "UNSAFE_DOM_SINK_INDICATOR",
      "WEBSOCKET_ENDPOINT_OBSERVED",
    ]);
    expect(results[0]?.evidence[0]?.excerpt).toContain("Data flow was not proven");
  });

  it("redacts WebSocket query values from client evidence", () => {
    const results = new ApplicationSurfaceScanner().analyze([
      exchange({
        finalUrl: "https://fixture.test/assets/socket.js",
        headers: { "content-type": "application/javascript" },
        body: 'const socket = "wss://fixture.test/events?token=do-not-retain";',
      }),
    ]);
    expect(results[0]?.observationType).toBe("WEBSOCKET_ENDPOINT_OBSERVED");
    expect(JSON.stringify(results)).not.toContain("do-not-retain");
    expect(JSON.stringify(results)).toContain("%5BREDACTED%5D");
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

  it("confirms an open redirect without following the external destination", async () => {
    const calls: string[] = [];
    const client = {
      request(url: string): Promise<ScopedResponse> {
        calls.push(url);
        return Promise.resolve({
          requestedUrl: url,
          finalUrl: url,
          statusCode: 302,
          headers: { location: "https://aasp-redirect-check.invalid/authorized-assessment" },
          body: Buffer.alloc(0),
          redirects: [],
        });
      },
    } as ScopedHttpClient;
    const result = await analyzeSafeApplicationInputs(
      client,
      ["https://fixture.test/redirect?next=%2Fhome"],
      { timeoutMs: 1_000, maxRequests: 1, requestsPerSecond: 10 },
    );
    expect(calls).toHaveLength(1);
    expect(result.requestsMade).toBe(1);
    expect(result.observations[0]?.observationType).toBe("OPEN_REDIRECT_CONFIRMED");
    expect(result.observations[0]?.evidence[0]?.requestMetadata).toMatchObject({
      followRedirects: false,
    });
  });

  it("uses only an inert marker when observing query reflection", async () => {
    const client = {
      request(url: string): Promise<ScopedResponse> {
        const marker = new URL(url).searchParams.get("q") ?? "";
        return Promise.resolve({
          requestedUrl: url,
          finalUrl: url,
          statusCode: 200,
          headers: { "content-type": "text/html" },
          body: Buffer.from(`<p>${marker}</p>`),
          redirects: [],
        });
      },
    } as ScopedHttpClient;
    const result = await analyzeSafeApplicationInputs(
      client,
      ["https://fixture.test/search?q=ok"],
      {
        timeoutMs: 1_000,
        maxRequests: 1,
        requestsPerSecond: 10,
      },
    );
    expect(result.observations[0]?.observationType).toBe("INPUT_REFLECTION_OBSERVED");
    expect(result.observations[0]?.metadata).toMatchObject({ executablePayloadUsed: false });
    expect(JSON.stringify(result)).not.toContain("<script>");
  });

  it("does not actively probe URLs containing sensitive query parameters", async () => {
    let called = false;
    const client = {
      request(): Promise<ScopedResponse> {
        called = true;
        throw new Error("request must not be issued");
      },
    } as ScopedHttpClient;
    const result = await analyzeSafeApplicationInputs(
      client,
      ["https://fixture.test/callback?access_token=secret&q=value"],
      { timeoutMs: 1_000, maxRequests: 2, requestsPerSecond: 10 },
    );
    expect(called).toBe(false);
    expect(result).toMatchObject({ observations: [], requestsMade: 0, failures: [] });
  });
});
