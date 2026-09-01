import type { ScannerObservationInput } from "@aasp/schemas";
import {
  observation,
  type HttpExchange,
  type PassiveScannerAdapter,
} from "@aasp/scanner-integrations";

export class MisconfigurationScanner implements PassiveScannerAdapter {
  readonly name = "aasp-misconfiguration";
  readonly version = "0.1.0";

  analyze(exchanges: readonly HttpExchange[]): ScannerObservationInput[] {
    const results: ScannerObservationInput[] = [];
    for (const exchange of exchanges) {
      const path = new URL(exchange.finalUrl).pathname;
      if (/\.map$/i.test(path) && exchange.statusCode === 200) {
        results.push(
          observation(
            this,
            exchange,
            "SOURCE_MAP_PUBLICLY_ACCESSIBLE",
            { path, contentObserved: exchange.body.length > 0 },
            { rawSeverity: "LOW", excerpt: exchange.body.slice(0, 1_024) },
          ),
        );
      }
      if (
        exchange.statusCode >= 500 &&
        /(?:stack|trace|exception|error:|\sat\s+[^\n]+\([^\n]+:\d+:\d+\))/i.test(exchange.body)
      ) {
        results.push(
          observation(
            this,
            exchange,
            "VERBOSE_ERROR_DETAILS_OBSERVED",
            { statusCode: exchange.statusCode, detector: "error-marker-and-stack-location" },
            { rawSeverity: "LOW", excerpt: exchange.body.slice(0, 2_048) },
          ),
        );
      }
    }
    return results;
  }
}
