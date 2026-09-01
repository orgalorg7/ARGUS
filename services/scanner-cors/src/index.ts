import type { ScannerObservationInput } from "@aasp/schemas";
import type { ScopedHttpClient, ScopedResponse } from "@aasp/scope-engine";

const probeOrigin = "https://aasp-invalid-origin.invalid";

function header(response: ScopedResponse, name: string): string {
  const value = response.headers[name.toLowerCase()];
  return Array.isArray(value) ? value.join(",") : (value ?? "");
}

function observationFor(
  url: string,
  method: "GET" | "OPTIONS",
  response: ScopedResponse,
  observationType: string,
  rawSeverity: string,
): ScannerObservationInput {
  const parsed = new URL(response.finalUrl);
  const allowOrigin = header(response, "access-control-allow-origin");
  const allowCredentials = header(response, "access-control-allow-credentials");
  return {
    scanner: "aasp-cors",
    scannerVersion: "0.1.0",
    observationType,
    asset: parsed.origin,
    endpoint: parsed.pathname,
    method,
    rawSeverity,
    evidence: [
      {
        source: "aasp-cors",
        asset: response.finalUrl,
        requestMetadata: { method, requestedUrl: url, origin: probeOrigin },
        responseMetadata: {
          statusCode: response.statusCode,
          accessControlAllowOrigin: allowOrigin,
          accessControlAllowCredentials: allowCredentials,
          vary: header(response, "vary"),
        },
        excerpt: `Origin: ${probeOrigin}\nAccess-Control-Allow-Origin: ${allowOrigin || "not observed"}\nAccess-Control-Allow-Credentials: ${allowCredentials || "not observed"}`,
      },
    ],
    metadata: { probeOrigin, allowOrigin, allowCredentials, statusCode: response.statusCode },
  };
}

export interface CorsScanResult {
  observations: ScannerObservationInput[];
  requestsMade: number;
  failures: Array<{ url: string; message: string }>;
}

export async function analyzeCors(
  client: ScopedHttpClient,
  urls: readonly string[],
  options: {
    timeoutMs: number;
    maxRequests: number;
    requestsPerSecond: number;
    isCancelled?: () => Promise<boolean>;
  },
): Promise<CorsScanResult> {
  const observations: ScannerObservationInput[] = [];
  const failures: Array<{ url: string; message: string }> = [];
  let requestsMade = 0;
  let previousRequestAt = 0;
  for (const url of [...new Set(urls)].slice(0, options.maxRequests)) {
    if (options.isCancelled && (await options.isCancelled())) break;
    try {
      const intervalMs = 1_000 / Math.max(0.1, options.requestsPerSecond);
      const waitMs = Math.max(0, previousRequestAt + intervalMs - Date.now());
      if (waitMs > 0) await new Promise((resolve) => setTimeout(resolve, waitMs));
      previousRequestAt = Date.now();
      const method = "GET" as const;
      const response = await client.request(url, {
        method,
        headers: { origin: probeOrigin },
        timeoutMs: options.timeoutMs,
        maxResponseBytes: 256 * 1024,
        followRedirects: false,
      });
      requestsMade += 1;
      const allowOrigin = header(response, "access-control-allow-origin");
      const credentials = header(response, "access-control-allow-credentials").toLowerCase();
      if (allowOrigin === probeOrigin && credentials === "true") {
        observations.push(
          observationFor(url, method, response, "CORS_ARBITRARY_ORIGIN_WITH_CREDENTIALS", "HIGH"),
        );
      } else if (allowOrigin === "*" && credentials === "true") {
        observations.push(
          observationFor(url, method, response, "CORS_WILDCARD_WITH_CREDENTIALS", "MEDIUM"),
        );
      } else if (allowOrigin) {
        observations.push(observationFor(url, method, response, "CORS_POLICY_OBSERVATION", "INFO"));
      }
    } catch (error: unknown) {
      failures.push({ url, message: error instanceof Error ? error.message : String(error) });
    }
  }
  return { observations, requestsMade, failures };
}
