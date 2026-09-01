import { describe, expect, it } from "vitest";
import {
  AsynchronousCrawler,
  CrawlTrapGuard,
  canonicalizeUrl,
  type CrawledPage,
} from "@aasp/crawler";
import {
  ScopeViolationError,
  type ScopedHttpClient,
  type ScopedResponse,
} from "@aasp/scope-engine";

class FixtureClient {
  readonly requested: string[] = [];

  request(url: string): Promise<ScopedResponse> {
    this.requested.push(url);
    const parsed = new URL(url);
    if (parsed.hostname !== "fixture.test") {
      return Promise.reject(
        new ScopeViolationError("HOST_NOT_AUTHORIZED", "Outside fixture scope.", url),
      );
    }
    const bodies: Record<string, string> = {
      "/": '<a href="/about?utm_source=test">About</a><a href="https://outside.test/path">Outside</a><form action="/session" method="post"><input name="email" type="email"></form>',
      "/about": '<script>const endpoint = "/api/users";</script>',
      "/api/users": '{"users":[]}',
    };
    const body = bodies[parsed.pathname] ?? "not found";
    return Promise.resolve({
      requestedUrl: url,
      finalUrl: url,
      statusCode: bodies[parsed.pathname] ? 200 : 404,
      headers: {
        "content-type": parsed.pathname.startsWith("/api/") ? "application/json" : "text/html",
      },
      body: Buffer.from(body),
      redirects: [],
    });
  }
}

function asScopedClient(client: FixtureClient): ScopedHttpClient {
  return client as unknown as ScopedHttpClient;
}

describe("crawler", () => {
  it("canonicalizes query order and removes tracking/session parameters", () => {
    expect(
      canonicalizeUrl(
        "https://Example.test:443/path?utm_source=x&b=2&sessionid=secret&a=1#fragment",
      ),
    ).toBe("https://example.test/path?a=1&b=2");
  });

  it("blocks excessive variants of the same crawl shape", () => {
    const guard = new CrawlTrapGuard(2);
    expect(guard.allow("https://fixture.test/calendar/2026/1")).toBe(true);
    expect(guard.allow("https://fixture.test/calendar/2026/2")).toBe(true);
    expect(guard.allow("https://fixture.test/calendar/2026/3")).toBe(false);
  });

  it("discovers pages and endpoints while recording an out-of-scope request block", async () => {
    const client = new FixtureClient();
    const crawler = new AsynchronousCrawler(asScopedClient(client), {
      maxDepth: 2,
      maxUrls: 20,
      maxRequests: 20,
      requestsPerSecond: 1_000,
      concurrency: 3,
      timeoutMs: 1_000,
      followRedirects: true,
      retries: 0,
    });
    const result = await crawler.crawl("https://fixture.test/");
    expect(result.cancelled).toBe(false);
    expect(result.pages.map((page) => page.canonicalUrl)).toContain("https://fixture.test/about");
    expect(
      result.pages.flatMap((page) => page.endpoints).map((endpoint) => endpoint.path),
    ).toContain("/session");
    expect(result.discoveredUrls.map((item) => item.canonicalUrl)).toContain(
      "https://fixture.test/about",
    );
    expect(result.requestsBlockedByScope).toBe(1);
    expect(result.requestsMade).toBeLessThanOrEqual(20);
  });

  it("stops between request batches when cancellation is persisted", async () => {
    const client = new FixtureClient();
    let checks = 0;
    const crawler = new AsynchronousCrawler(
      asScopedClient(client),
      {
        maxDepth: 2,
        maxUrls: 20,
        maxRequests: 20,
        requestsPerSecond: 1_000,
        concurrency: 1,
        timeoutMs: 1_000,
        followRedirects: true,
      },
      { isCancelled: () => Promise.resolve((checks += 1) > 1) },
    );
    const result = await crawler.crawl("https://fixture.test/");
    expect(result.cancelled).toBe(true);
    expect(result.requestsMade).toBe(1);
  });
});

export function pageFixture(overrides: Partial<CrawledPage> = {}): CrawledPage {
  return {
    url: "https://fixture.test/openapi.json",
    canonicalUrl: "https://fixture.test/openapi.json",
    finalUrl: "https://fixture.test/openapi.json",
    depth: 0,
    discoveredBy: "TEST",
    statusCode: 200,
    contentType: "application/json",
    headers: { "content-type": "application/json" },
    bodyText: "{}",
    links: [],
    scripts: [],
    endpoints: [],
    redirects: [],
    ...overrides,
  };
}
