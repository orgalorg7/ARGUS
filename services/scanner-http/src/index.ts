import type { ScannerObservationInput } from "@aasp/schemas";
import {
  headerValues,
  observation,
  type HttpExchange,
  type PassiveScannerAdapter,
} from "@aasp/scanner-integrations";

export class HttpSecurityScanner implements PassiveScannerAdapter {
  readonly name = "aasp-http";
  readonly version = "0.1.0";

  analyze(exchanges: readonly HttpExchange[]): ScannerObservationInput[] {
    const results: ScannerObservationInput[] = [];
    for (const exchange of exchanges) {
      const contentType = headerValues(exchange.headers, "content-type")[0] ?? "";
      results.push(
        observation(this, exchange, "HTTP_RESPONSE_PROFILE", {
          statusCode: exchange.statusCode,
          contentType,
          redirectCount: exchange.redirects.length,
        }),
      );
      for (const name of ["server", "x-powered-by", "x-aspnet-version"]) {
        const values = headerValues(exchange.headers, name);
        if (values.length === 0) continue;
        results.push(
          observation(
            this,
            exchange,
            "SERVER_TECHNOLOGY_DISCLOSURE",
            { header: name, observed: values },
            { rawSeverity: "INFO", excerpt: `${name}: ${values.join(", ")}` },
          ),
        );
      }
      const cacheControl = headerValues(exchange.headers, "cache-control").join(",").toLowerCase();
      const hasSessionCookie = headerValues(exchange.headers, "set-cookie").some((value) =>
        /(?:session|auth|token|sid)/i.test(value.split("=", 1)[0] ?? ""),
      );
      if (hasSessionCookie && !/(?:no-store|private)/.test(cacheControl)) {
        results.push(
          observation(
            this,
            exchange,
            "SESSION_RESPONSE_CACHE_POLICY_WEAK",
            { cacheControl: cacheControl || null },
            { rawSeverity: "LOW", excerpt: "Session-indicating response lacks no-store/private." },
          ),
        );
      }
    }
    return results;
  }
}
