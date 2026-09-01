import type { ScannerObservationInput } from "@aasp/schemas";
import {
  headerValues,
  observation,
  type HttpExchange,
  type PassiveScannerAdapter,
} from "@aasp/scanner-integrations";

export class HeaderSecurityScanner implements PassiveScannerAdapter {
  readonly name = "aasp-headers";
  readonly version = "0.1.0";

  analyze(exchanges: readonly HttpExchange[]): ScannerObservationInput[] {
    const results: ScannerObservationInput[] = [];
    for (const exchange of exchanges) {
      const contentType = headerValues(exchange.headers, "content-type").join(";").toLowerCase();
      const isDocument = contentType.includes("text/html");
      if (!isDocument || exchange.statusCode < 200 || exchange.statusCode >= 400) continue;
      const csp = headerValues(exchange.headers, "content-security-policy").join(";");
      const checks = [
        {
          name: "content-security-policy",
          type: "CONTENT_SECURITY_POLICY_MISSING",
          severity: "LOW",
        },
        { name: "x-content-type-options", type: "NOSNIFF_HEADER_MISSING", severity: "LOW" },
        { name: "referrer-policy", type: "REFERRER_POLICY_MISSING", severity: "INFO" },
        { name: "permissions-policy", type: "PERMISSIONS_POLICY_MISSING", severity: "INFO" },
      ];
      for (const check of checks) {
        if (headerValues(exchange.headers, check.name).length > 0) continue;
        results.push(
          observation(
            this,
            exchange,
            check.type,
            { missingHeader: check.name, context: "successful HTML document" },
            { rawSeverity: check.severity, excerpt: `${check.name}: not observed` },
          ),
        );
      }
      const xFrameOptions = headerValues(exchange.headers, "x-frame-options");
      if (xFrameOptions.length === 0 && !/frame-ancestors/i.test(csp)) {
        results.push(
          observation(
            this,
            exchange,
            "FRAME_PROTECTION_MISSING",
            { xFrameOptionsObserved: false, cspFrameAncestorsObserved: false },
            { rawSeverity: "LOW", excerpt: "No X-Frame-Options or CSP frame-ancestors observed." },
          ),
        );
      }
      if (
        new URL(exchange.finalUrl).protocol === "https:" &&
        headerValues(exchange.headers, "strict-transport-security").length === 0
      ) {
        results.push(
          observation(
            this,
            exchange,
            "HSTS_HEADER_MISSING",
            { context: "HTTPS response" },
            { rawSeverity: "LOW", excerpt: "Strict-Transport-Security: not observed" },
          ),
        );
      }
    }
    return results;
  }
}
