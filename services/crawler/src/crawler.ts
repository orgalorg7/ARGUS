import * as cheerio from "cheerio";
import { XMLParser } from "fast-xml-parser";
import { ScopeViolationError, type ScopedHttpClient } from "@aasp/scope-engine";
import { canonicalizeUrl, CrawlTrapError } from "./canonical-url.js";
import { CrawlTrapGuard } from "./crawl-trap-guard.js";
import type {
  CrawlConfig,
  CrawlFailure,
  CrawlHooks,
  CrawlResult,
  CrawledPage,
  EndpointCandidate,
} from "./types.js";

interface QueueItem {
  url: string;
  depth: number;
  discoveredBy: string;
  priority: number;
}

const textualTypes = [
  "text/",
  "application/json",
  "application/xml",
  "application/javascript",
  "image/svg+xml",
];
const initialPaths = [
  "/",
  "/robots.txt",
  "/sitemap.xml",
  "/.well-known/security.txt",
  "/openapi.json",
  "/swagger.json",
];

class RateGate {
  private nextAt = 0;

  constructor(private readonly requestsPerSecond: number) {}

  async wait(): Promise<void> {
    const interval = Math.ceil(1_000 / this.requestsPerSecond);
    const waitMs = Math.max(0, this.nextAt - Date.now());
    this.nextAt = Math.max(Date.now(), this.nextAt) + interval;
    if (waitMs > 0) await new Promise((resolve) => setTimeout(resolve, waitMs));
  }
}

function headerRecord(headers: NodeJS.Dict<string | string[]>): Record<string, string | string[]> {
  return Object.fromEntries(
    Object.entries(headers).filter(
      (entry): entry is [string, string | string[]] => entry[1] !== undefined,
    ),
  );
}

function contentType(headers: Record<string, string | string[]>): string {
  const value = headers["content-type"];
  return (
    (Array.isArray(value) ? value[0] : value)?.split(";")[0]?.trim().toLowerCase() ?? "unknown"
  );
}

function queryParameters(url: URL) {
  return [...new Set(url.searchParams.keys())].map((name) => ({
    name,
    location: "QUERY" as const,
  }));
}

function endpointFromUrl(url: URL, source: string): EndpointCandidate {
  const canonical = new URL(canonicalizeUrl(url.toString()));
  return {
    asset: canonical.origin,
    path: canonical.pathname,
    method: "GET",
    source,
    parameters: queryParameters(canonical),
  };
}

function extractHtml(
  body: string,
  pageUrl: string,
): {
  links: string[];
  scripts: string[];
  endpoints: EndpointCandidate[];
} {
  const $ = cheerio.load(body);
  const baseHref = $("base[href]").first().attr("href");
  let resolutionBase = pageUrl;
  if (baseHref) {
    try {
      resolutionBase = new URL(baseHref, pageUrl).toString();
    } catch {
      resolutionBase = pageUrl;
    }
  }
  const links: string[] = [];
  const scripts: string[] = [];
  const endpoints: EndpointCandidate[] = [];
  $("a[href], link[href]").each((_index, element) => {
    const href = $(element).attr("href");
    if (!href) return;
    try {
      links.push(new URL(href, resolutionBase).toString());
    } catch {
      return;
    }
  });
  $("script[src]").each((_index, element) => {
    const src = $(element).attr("src");
    if (!src) return;
    try {
      const resolved = new URL(src, resolutionBase).toString();
      scripts.push(resolved);
      links.push(resolved);
    } catch {
      return;
    }
  });
  $("form").each((_index, form) => {
    const action = $(form).attr("action") ?? pageUrl;
    const method = ($(form).attr("method") ?? "GET").toUpperCase();
    let resolved: URL;
    try {
      resolved = new URL(action, resolutionBase);
    } catch {
      return;
    }
    const parameters = $(form)
      .find("input[name], select[name], textarea[name]")
      .toArray()
      .map((element) => ({
        name: $(element).attr("name") as string,
        location: method === "GET" ? ("QUERY" as const) : ("FORM" as const),
        observedType: $(element).attr("type") ?? element.tagName,
      }));
    endpoints.push({
      asset: resolved.origin,
      path: resolved.pathname,
      method,
      source: "HTML_FORM",
      parameters,
    });
  });
  for (const link of links) {
    const parsed = new URL(link);
    if (
      /\/(?:api|graphql|oauth|auth|login|logout|register|signup|password|session)(?:\/|$)/i.test(
        parsed.pathname,
      )
    ) {
      endpoints.push(endpointFromUrl(parsed, "HTML_LINK"));
    }
  }
  const inlineScript = $("script:not([src])")
    .map((_index, element) => $(element).text())
    .get()
    .join("\n");
  const routePattern =
    /["'`]((?:https?:\/\/[^"'`\s]+)|(?:\/(?:api|graphql|oauth|auth)\/[^"'`\s?#]*))["'`]/gi;
  for (const match of inlineScript.matchAll(routePattern)) {
    const route = match[1];
    if (!route) continue;
    try {
      const parsed = new URL(route, pageUrl);
      endpoints.push(endpointFromUrl(parsed, "INLINE_SCRIPT_ROUTE"));
      links.push(parsed.toString());
    } catch {
      continue;
    }
  }
  return { links, scripts, endpoints };
}

function sitemapLinks(body: string): string[] {
  try {
    const parsed = new XMLParser({ ignoreAttributes: true }).parse(body) as Record<string, unknown>;
    const root = parsed["urlset"] ?? parsed["sitemapindex"];
    if (!root || typeof root !== "object") return [];
    const entries =
      (root as Record<string, unknown>)["url"] ?? (root as Record<string, unknown>)["sitemap"];
    const list = Array.isArray(entries) ? entries : entries ? [entries] : [];
    return list.flatMap((entry) => {
      if (!entry || typeof entry !== "object") return [];
      const location = (entry as Record<string, unknown>)["loc"];
      return typeof location === "string" ? [location] : [];
    });
  } catch {
    return [];
  }
}

function robotsLinks(body: string): string[] {
  return body
    .split(/\r?\n/)
    .map((line) => /^\s*Sitemap\s*:\s*(\S+)\s*$/i.exec(line)?.[1])
    .filter((value): value is string => Boolean(value));
}

export class AsynchronousCrawler {
  constructor(
    private readonly client: ScopedHttpClient,
    private readonly config: CrawlConfig,
    private readonly hooks: CrawlHooks = {},
  ) {}

  async crawl(targetOrigin: string, includeWellKnownSeeds = false): Promise<CrawlResult> {
    const queue: QueueItem[] = [];
    const seen = new Set<string>();
    const discovered = new Map<string, QueueItem>();
    const pages: CrawledPage[] = [];
    const failures: CrawlFailure[] = [];
    const trapGuard = new CrawlTrapGuard();
    const rateGate = new RateGate(this.config.requestsPerSecond);
    let requestsMade = 0;
    let requestsBlockedByScope = 0;
    let trapBlockedUrls = 0;
    let cancelled = false;

    const enqueue = (
      candidate: string,
      depth: number,
      discoveredBy: string,
      priority = depth,
    ): void => {
      if (depth > this.config.maxDepth || discovered.size >= this.config.maxUrls) return;
      let canonical: string;
      try {
        canonical = canonicalizeUrl(candidate, targetOrigin);
      } catch (error: unknown) {
        if (error instanceof CrawlTrapError) trapBlockedUrls += 1;
        return;
      }
      if (seen.has(canonical) || discovered.has(canonical)) return;
      if (!trapGuard.allow(canonical)) {
        trapBlockedUrls += 1;
        failures.push({
          url: canonical,
          category: "TRAP_BLOCKED",
          message: "Crawl-shape limit reached.",
        });
        return;
      }
      const item = { url: canonical, depth, discoveredBy, priority };
      discovered.set(canonical, item);
      queue.push(item);
    };

    if (includeWellKnownSeeds) {
      for (const path of initialPaths)
        enqueue(new URL(path, targetOrigin).toString(), 0, "DISCOVERY_SEED", -1);
    } else {
      enqueue(targetOrigin, 0, "CRAWL_SEED", 0);
    }

    const fetchItem = async (item: QueueItem): Promise<void> => {
      if (requestsMade >= this.config.maxRequests) return;
      seen.add(item.url);
      requestsMade += 1;
      await rateGate.wait();
      const retries = this.config.retries ?? 1;
      let lastError: unknown;
      for (let attempt = 0; attempt <= retries; attempt += 1) {
        try {
          const response = await this.client.request(item.url, {
            method: "GET",
            timeoutMs: this.config.timeoutMs,
            maxResponseBytes: this.config.maxResponseBytes ?? 2 * 1024 * 1024,
            followRedirects: this.config.followRedirects,
            maxRedirects: 5,
          });
          const headers = headerRecord(response.headers);
          const type = contentType(headers);
          if (!textualTypes.some((prefix) => type.startsWith(prefix))) {
            failures.push({
              url: item.url,
              category: "CONTENT_SKIPPED",
              message: `Content type ${type} was not parsed.`,
            });
          }
          const bodyText = textualTypes.some((prefix) => type.startsWith(prefix))
            ? response.body.toString("utf8")
            : "";
          let links: string[] = [];
          let scripts: string[] = [];
          let endpoints: EndpointCandidate[] = [
            endpointFromUrl(new URL(response.finalUrl), item.discoveredBy),
          ];
          if (type === "text/html") {
            const extracted = extractHtml(bodyText, response.finalUrl);
            links = extracted.links;
            scripts = extracted.scripts;
            endpoints = [...endpoints, ...extracted.endpoints];
          } else if (type.includes("xml") || response.finalUrl.endsWith("sitemap.xml")) {
            links = sitemapLinks(bodyText);
          } else if (response.finalUrl.endsWith("robots.txt")) {
            links = robotsLinks(bodyText);
          }
          const page: CrawledPage = {
            url: item.url,
            canonicalUrl: canonicalizeUrl(response.finalUrl),
            depth: item.depth,
            discoveredBy: item.discoveredBy,
            statusCode: response.statusCode,
            contentType: type,
            headers,
            bodyText,
            links,
            scripts,
            endpoints,
            finalUrl: response.finalUrl,
            redirects: response.redirects,
          };
          pages.push(page);
          for (const link of links) enqueue(link, item.depth + 1, "PAGE_REFERENCE");
          await this.hooks.onPage?.(page, { requestsMade, discoveredUrls: discovered.size });
          return;
        } catch (error: unknown) {
          lastError = error;
          if (error instanceof ScopeViolationError) {
            requestsBlockedByScope += 1;
            failures.push({ url: item.url, category: "SCOPE_BLOCKED", message: error.message });
            return;
          }
        }
      }
      failures.push({
        url: item.url,
        category: "REQUEST_FAILED",
        message:
          lastError instanceof Error
            ? lastError.message
            : "Request failed without an Error object.",
      });
    };

    while (queue.length > 0 && requestsMade < this.config.maxRequests) {
      if (await this.hooks.isCancelled?.()) {
        cancelled = true;
        break;
      }
      queue.sort(
        (left, right) => left.priority - right.priority || left.url.localeCompare(right.url),
      );
      const batch = queue.splice(
        0,
        Math.min(this.config.concurrency, this.config.maxRequests - requestsMade),
      );
      await Promise.all(batch.map(fetchItem));
    }

    return {
      pages,
      discoveredUrls: [...discovered.entries()].map(([canonicalUrl, item]) => ({
        url: item.url,
        canonicalUrl,
        depth: item.depth,
        discoveredBy: item.discoveredBy,
      })),
      requestsMade,
      requestsBlockedByScope,
      trapBlockedUrls,
      failures,
      cancelled,
    };
  }
}
