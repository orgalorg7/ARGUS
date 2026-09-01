import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { discoverApiEndpoints } from "@aasp/api-discovery";
import { AsynchronousCrawler } from "@aasp/crawler";
import { ScopeEngine, ScopedHttpClient } from "@aasp/scope-engine";
import { fingerprintTechnologies } from "@aasp/technology-fingerprinter";

const targetOrigin = process.env["FIXTURE_URL"] ?? "http://127.0.0.1:4010";
const parsed = new URL(targetOrigin);
const client = new ScopedHttpClient(new ScopeEngine(), {
  targetOrigin,
  includeSubdomains: false,
  allowPrivateNetwork: true,
  allowedPorts: [parsed.port ? Number(parsed.port) : parsed.protocol === "https:" ? 443 : 80],
});
const crawler = new AsynchronousCrawler(client, {
  maxDepth: 3,
  maxUrls: 100,
  maxRequests: 100,
  requestsPerSecond: 20,
  concurrency: 4,
  timeoutMs: 5_000,
  followRedirects: true,
  retries: 1,
});

const result = await crawler.crawl(targetOrigin, true);
if (result.pages.length === 0)
  throw new Error("The fixture crawl completed without any response pages.");
const endpoints = discoverApiEndpoints(result.pages);
const technologies = fingerprintTechnologies(result.pages);
const artifact = {
  generatedAt: new Date().toISOString(),
  targetOrigin,
  coverage: {
    requestsMade: result.requestsMade,
    pagesReceived: result.pages.length,
    urlsDiscovered: result.discoveredUrls.length,
    requestsBlockedByScope: result.requestsBlockedByScope,
    trapBlockedUrls: result.trapBlockedUrls,
    failures: result.failures,
  },
  pages: result.pages.map((page) => ({
    url: page.finalUrl,
    statusCode: page.statusCode,
    contentType: page.contentType,
    depth: page.depth,
  })),
  endpoints,
  technologies,
};
const artifactDirectory = resolve(process.cwd(), "../../artifacts");
await mkdir(artifactDirectory, { recursive: true });
const artifactPath = resolve(artifactDirectory, "day2-crawl-result.json");
await writeFile(artifactPath, `${JSON.stringify(artifact, null, 2)}\n`, "utf8");
process.stdout.write(`${JSON.stringify({ artifactPath, ...artifact.coverage })}\n`);
