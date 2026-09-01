export interface CrawlConfig {
  maxDepth: number;
  maxUrls: number;
  maxRequests: number;
  requestsPerSecond: number;
  concurrency: number;
  timeoutMs: number;
  followRedirects: boolean;
  maxResponseBytes?: number;
  retries?: number;
}

export interface DiscoveredParameterCandidate {
  name: string;
  location: "QUERY" | "PATH" | "FORM" | "HEADER" | "BODY";
  observedType?: string;
}

export interface EndpointCandidate {
  asset: string;
  path: string;
  method: string;
  source: string;
  parameters: DiscoveredParameterCandidate[];
}

export interface CrawledPage {
  url: string;
  canonicalUrl: string;
  depth: number;
  discoveredBy: string;
  statusCode: number;
  contentType: string;
  headers: Record<string, string | string[]>;
  bodyText: string;
  links: string[];
  scripts: string[];
  endpoints: EndpointCandidate[];
  finalUrl: string;
  redirects: string[];
}

export interface CrawlFailure {
  url: string;
  category: "SCOPE_BLOCKED" | "REQUEST_FAILED" | "CONTENT_SKIPPED" | "TRAP_BLOCKED";
  message: string;
}

export interface DiscoveredUrlRecord {
  url: string;
  canonicalUrl: string;
  depth: number;
  discoveredBy: string;
}

export interface CrawlResult {
  pages: CrawledPage[];
  discoveredUrls: DiscoveredUrlRecord[];
  requestsMade: number;
  requestsBlockedByScope: number;
  trapBlockedUrls: number;
  failures: CrawlFailure[];
  cancelled: boolean;
}

export interface CrawlHooks {
  isCancelled?: () => Promise<boolean>;
  onPage?: (
    page: CrawledPage,
    progress: { requestsMade: number; discoveredUrls: number },
  ) => Promise<void>;
}
