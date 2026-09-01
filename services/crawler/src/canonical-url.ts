const trackingParameters = new Set([
  "fbclid",
  "gclid",
  "dclid",
  "mc_cid",
  "mc_eid",
  "ref",
  "referrer",
]);
const sessionParameters = /^(?:sid|session|sessionid|phpsessid|jsessionid|token)$/i;

export class CrawlTrapError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CrawlTrapError";
  }
}

export function canonicalizeUrl(input: string, base?: string): string {
  const url = base ? new URL(input, base) : new URL(input);
  url.hash = "";
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new CrawlTrapError(`Scheme ${url.protocol} is not crawlable.`);
  }
  if (url.toString().length > 2_048)
    throw new CrawlTrapError("URL exceeds the 2,048 character limit.");
  const retained: Array<[string, string]> = [];
  for (const [name, value] of url.searchParams.entries()) {
    const lower = name.toLowerCase();
    if (lower.startsWith("utm_") || trackingParameters.has(lower) || sessionParameters.test(name))
      continue;
    retained.push([name, value]);
  }
  if (retained.length > 20) throw new CrawlTrapError("URL contains too many query parameters.");
  retained.sort(([leftName, leftValue], [rightName, rightValue]) =>
    leftName === rightName
      ? leftValue.localeCompare(rightValue)
      : leftName.localeCompare(rightName),
  );
  url.search = "";
  for (const [name, value] of retained) url.searchParams.append(name, value);
  url.pathname = url.pathname.replace(/\/{2,}/g, "/");
  const segments = url.pathname.split("/").filter(Boolean);
  if (segments.length > 30) throw new CrawlTrapError("URL path contains too many segments.");
  const segmentCounts = new Map<string, number>();
  for (const segment of segments) {
    const normalized = decodeURIComponent(segment).toLowerCase();
    const count = (segmentCounts.get(normalized) ?? 0) + 1;
    segmentCounts.set(normalized, count);
    if (count > 4) throw new CrawlTrapError("URL contains recursively repeated path segments.");
  }
  if (
    (url.protocol === "http:" && url.port === "80") ||
    (url.protocol === "https:" && url.port === "443")
  ) {
    url.port = "";
  }
  return url.toString();
}

export function crawlShape(input: string): string {
  const url = new URL(input);
  const path = url.pathname
    .replace(/\b\d{4}[-/]\d{1,2}[-/]\d{1,2}\b/g, ":date")
    .replace(/\b\d{4}\b/g, ":year")
    .replace(/\b\d+\b/g, ":number")
    .replace(/[a-f0-9]{16,}/gi, ":identifier");
  const queryKeys = [...url.searchParams.keys()].sort().join(",");
  return `${url.origin}${path}?${queryKeys}`;
}
