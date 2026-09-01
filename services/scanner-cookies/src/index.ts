import type { ScannerObservationInput } from "@aasp/schemas";
import {
  headerValues,
  observation,
  type HttpExchange,
  type PassiveScannerAdapter,
} from "@aasp/scanner-integrations";

export interface ParsedCookie {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: "Strict" | "Lax" | "None" | null;
  domain: string | null;
  path: string | null;
  expires: string | null;
}

export function parseSetCookie(value: string): ParsedCookie | null {
  const segments = value.split(";").map((part) => part.trim());
  const separator = segments[0]?.indexOf("=") ?? -1;
  if (separator <= 0) return null;
  const name = segments[0]?.slice(0, separator).trim() ?? "";
  const attributes = new Map<string, string>();
  for (const segment of segments.slice(1)) {
    const [rawName, ...rest] = segment.split("=");
    if (rawName) attributes.set(rawName.toLowerCase(), rest.join("="));
  }
  const sameSiteValue = attributes.get("samesite")?.toLowerCase();
  const sameSite =
    sameSiteValue === "strict"
      ? "Strict"
      : sameSiteValue === "lax"
        ? "Lax"
        : sameSiteValue === "none"
          ? "None"
          : null;
  return {
    name,
    secure: attributes.has("secure"),
    httpOnly: attributes.has("httponly"),
    sameSite,
    domain: attributes.get("domain") ?? null,
    path: attributes.get("path") ?? null,
    expires: attributes.get("expires") ?? null,
  };
}

export class CookieSecurityScanner implements PassiveScannerAdapter {
  readonly name = "aasp-cookies";
  readonly version = "0.1.0";

  analyze(exchanges: readonly HttpExchange[]): ScannerObservationInput[] {
    const results: ScannerObservationInput[] = [];
    for (const exchange of exchanges) {
      for (const rawCookie of headerValues(exchange.headers, "set-cookie")) {
        const cookie = parseSetCookie(rawCookie);
        if (!cookie) continue;
        const sessionLike = /(?:session|auth|token|sid)/i.test(cookie.name);
        const safeExcerpt = `Set-Cookie: ${cookie.name}=[REDACTED]; attributes=${
          [
            cookie.secure ? "Secure" : "",
            cookie.httpOnly ? "HttpOnly" : "",
            cookie.sameSite ? `SameSite=${cookie.sameSite}` : "",
          ]
            .filter(Boolean)
            .join(",") || "none"
        }`;
        const safeExchange: HttpExchange = {
          ...exchange,
          headers: {
            ...Object.fromEntries(
              Object.entries(exchange.headers).filter(
                ([name]) => name.toLowerCase() !== "set-cookie",
              ),
            ),
            "set-cookie": safeExcerpt,
          },
        };
        const common = { cookieName: cookie.name, sessionLike, attributes: cookie };
        if (!cookie.secure) {
          results.push(
            observation(this, safeExchange, "COOKIE_SECURE_ATTRIBUTE_MISSING", common, {
              rawSeverity: new URL(exchange.finalUrl).protocol === "https:" ? "MEDIUM" : "LOW",
              excerpt: safeExcerpt,
            }),
          );
        }
        if (sessionLike && !cookie.httpOnly) {
          results.push(
            observation(this, safeExchange, "SESSION_COOKIE_HTTPONLY_MISSING", common, {
              rawSeverity: "MEDIUM",
              excerpt: safeExcerpt,
            }),
          );
        }
        if (!cookie.sameSite || (cookie.sameSite === "None" && !cookie.secure)) {
          results.push(
            observation(this, safeExchange, "COOKIE_SAMESITE_WEAK_OR_MISSING", common, {
              rawSeverity: sessionLike ? "MEDIUM" : "LOW",
              excerpt: safeExcerpt,
            }),
          );
        }
      }
    }
    return results;
  }
}
