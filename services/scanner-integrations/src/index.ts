import type { ScannerEvidenceInput, ScannerObservationInput } from "@aasp/schemas";

export interface HttpExchange {
  requestedUrl: string;
  finalUrl: string;
  method: string;
  statusCode: number;
  headers: Record<string, string | string[]>;
  body: string;
  redirects: string[];
}

export interface PassiveScannerAdapter {
  readonly name: string;
  readonly version: string;
  analyze(exchanges: readonly HttpExchange[]): ScannerObservationInput[];
}

export function headerValues(
  headers: Readonly<Record<string, string | string[]>>,
  name: string,
): string[] {
  const value = Object.entries(headers).find(
    ([key]) => key.toLowerCase() === name.toLowerCase(),
  )?.[1];
  if (Array.isArray(value)) return value;
  return value === undefined ? [] : [value];
}

export function evidenceFor(
  exchange: HttpExchange,
  source: string,
  excerpt = "",
): ScannerEvidenceInput {
  return {
    source,
    asset: exchange.finalUrl,
    requestMetadata: { method: exchange.method, requestedUrl: exchange.requestedUrl },
    responseMetadata: {
      finalUrl: exchange.finalUrl,
      statusCode: exchange.statusCode,
      headers: exchange.headers,
      redirects: exchange.redirects,
    },
    excerpt: excerpt || exchange.body.slice(0, 8_192),
  };
}

export function observation(
  adapter: Pick<PassiveScannerAdapter, "name" | "version">,
  exchange: HttpExchange,
  observationType: string,
  metadata: Record<string, unknown>,
  options: { rawSeverity?: string; excerpt?: string; method?: string; parameter?: string } = {},
): ScannerObservationInput {
  const parsed = new URL(exchange.finalUrl);
  return {
    scanner: adapter.name,
    scannerVersion: adapter.version,
    observationType,
    asset: parsed.origin,
    endpoint: parsed.pathname,
    method: options.method ?? exchange.method,
    ...(options.parameter ? { parameter: options.parameter } : {}),
    ...(options.rawSeverity ? { rawSeverity: options.rawSeverity } : {}),
    evidence: [evidenceFor(exchange, adapter.name, options.excerpt)],
    metadata,
  };
}

export function runPassiveAdapters(
  adapters: readonly PassiveScannerAdapter[],
  exchanges: readonly HttpExchange[],
): ScannerObservationInput[] {
  return adapters.flatMap((adapter) => adapter.analyze(exchanges));
}
