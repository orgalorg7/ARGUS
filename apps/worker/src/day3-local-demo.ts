import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { AsynchronousCrawler } from "@aasp/crawler";
import { AuthenticationSurfaceScanner } from "@aasp/scanner-auth-surface";
import { CookieSecurityScanner } from "@aasp/scanner-cookies";
import { analyzeCors } from "@aasp/scanner-cors";
import { HeaderSecurityScanner } from "@aasp/scanner-headers";
import { HttpSecurityScanner } from "@aasp/scanner-http";
import { runPassiveAdapters, type HttpExchange } from "@aasp/scanner-integrations";
import { MisconfigurationScanner } from "@aasp/scanner-misconfiguration";
import { ScopeEngine, ScopedHttpClient } from "@aasp/scope-engine";
import { redactUnknown } from "@aasp/security-core";

const targetUrl = process.env["DAY3_DEMO_TARGET"] ?? "http://127.0.0.1:4010";
const target = new URL(targetUrl);
if (!new Set(["127.0.0.1", "::1"]).has(target.hostname)) {
  throw new Error("The Day 3 local demo is restricted to an explicit loopback fixture target.");
}

const policy = {
  targetOrigin: target.origin,
  includeSubdomains: false,
  allowPrivateNetwork: true,
  allowedPorts: [Number(target.port || (target.protocol === "https:" ? 443 : 80))],
};
const client = new ScopedHttpClient(new ScopeEngine(), policy);
const crawl = await new AsynchronousCrawler(client, {
  maxDepth: 3,
  maxUrls: 50,
  maxRequests: 40,
  requestsPerSecond: 10,
  concurrency: 4,
  timeoutMs: 5_000,
  followRedirects: true,
  retries: 0,
}).crawl(target.origin);

const exchanges: HttpExchange[] = crawl.pages.map((page) => ({
  requestedUrl: page.url,
  finalUrl: page.finalUrl,
  method: "GET",
  statusCode: page.statusCode,
  headers: page.headers,
  body: page.bodyText,
  redirects: page.redirects,
}));
const passive = runPassiveAdapters(
  [
    new HttpSecurityScanner(),
    new HeaderSecurityScanner(),
    new CookieSecurityScanner(),
    new AuthenticationSurfaceScanner(),
    new MisconfigurationScanner(),
  ],
  exchanges,
);
const corsUrls = crawl.pages
  .filter((page) => new URL(page.finalUrl).pathname.includes("cors"))
  .map((page) => page.finalUrl);
const active = await analyzeCors(client, corsUrls, {
  timeoutMs: 5_000,
  maxRequests: 10,
  requestsPerSecond: 10,
});
const observations = [...passive, ...active.observations];
const counts = Object.fromEntries(
  [...new Set(observations.map((item) => item.observationType))]
    .sort()
    .map((type) => [type, observations.filter((item) => item.observationType === type).length]),
);
const artifact = {
  target: target.origin,
  generatedAt: new Date().toISOString(),
  crawl: {
    requestsMade: crawl.requestsMade,
    pagesReceived: crawl.pages.length,
    requestsBlockedByScope: crawl.requestsBlockedByScope,
    failures: crawl.failures,
  },
  safeActive: {
    requestsMade: active.requestsMade,
    failures: active.failures,
  },
  observationCount: observations.length,
  observationTypeCounts: counts,
  observations: redactUnknown(observations),
};
const artifactDirectory = resolve(process.cwd(), "../../artifacts");
await mkdir(artifactDirectory, { recursive: true });
const artifactPath = resolve(artifactDirectory, "day3-scanner-observations.json");
await writeFile(artifactPath, `${JSON.stringify(artifact, null, 2)}\n`, "utf8");
process.stdout.write(
  `${JSON.stringify({ artifactPath, ...artifact.crawl, safeActiveRequests: active.requestsMade, observationCount: observations.length, observationTypeCounts: counts })}\n`,
);
