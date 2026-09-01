import type { ScannerObservationInput } from "@aasp/schemas";
import {
  observation,
  type HttpExchange,
  type PassiveScannerAdapter,
} from "@aasp/scanner-integrations";

const patterns: Array<[RegExp, string]> = [
  [/\/(?:login|signin|session)(?:\/|$)/i, "LOGIN_OR_SESSION"],
  [/\/(?:logout|signout)(?:\/|$)/i, "LOGOUT"],
  [/\/(?:register|signup)(?:\/|$)/i, "REGISTRATION"],
  [/\/(?:forgot|reset|password-reset)(?:[-/]|$)/i, "PASSWORD_RECOVERY"],
  [/\/(?:mfa|2fa|webauthn)(?:\/|$)/i, "MFA"],
  [/\/(?:oauth|oidc|auth)\/(?:callback|authorize|token)(?:\/|$)/i, "FEDERATED_AUTH"],
];

export class AuthenticationSurfaceScanner implements PassiveScannerAdapter {
  readonly name = "aasp-auth-surface";
  readonly version = "0.1.0";

  analyze(exchanges: readonly HttpExchange[]): ScannerObservationInput[] {
    const results: ScannerObservationInput[] = [];
    const seen = new Set<string>();
    for (const exchange of exchanges) {
      const path = new URL(exchange.finalUrl).pathname;
      for (const [pattern, surfaceType] of patterns) {
        if (!pattern.test(path)) continue;
        const key = `${surfaceType}|${exchange.method}|${path}`;
        if (seen.has(key)) continue;
        seen.add(key);
        results.push(
          observation(
            this,
            exchange,
            "AUTHENTICATION_SURFACE_OBSERVED",
            { surfaceType, statusCode: exchange.statusCode },
            { rawSeverity: "INFO", excerpt: `Observed ${surfaceType} surface at ${path}.` },
          ),
        );
      }
    }
    return results;
  }
}
