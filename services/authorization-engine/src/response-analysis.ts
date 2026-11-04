import { createHash } from "node:crypto";
import { redactHeaders, redactText, redactUnknown } from "@aasp/security-core";
import type { IncomingHttpHeaders } from "node:http";
import type {
  AuthorizationDifference,
  AuthorizationObservation,
  NormalizedResponse,
  AuthenticationState,
} from "./types.js";

export function authenticationStateAfterResponse(
  current: AuthenticationState,
  statusCode: number,
): AuthenticationState {
  if (current === "AUTHENTICATED" && statusCode === 401) return "AUTH_EXPIRED";
  if (current === "AUTH_REFRESHING" && statusCode < 400) return "AUTHENTICATED";
  return current;
}

const defaultVolatileField =
  /(^|\.)(timestamp|createdAt|updatedAt|requestId|traceId|correlationId|csrf|nonce|cursor|uuid)$/i;
const defaultSensitiveField =
  /(^|\.)(email|phone|address|token|secret|apiKey|nationalId|payment|billing|internalNotes|password|session|ssn|creditCard)(\.|$)/i;
const selectedResponseHeaders = new Set([
  "cache-control",
  "content-type",
  "location",
  "vary",
  "www-authenticate",
]);

function stable(value: unknown, path = "$"): unknown {
  if (Array.isArray(value)) return value.map((entry, index) => stable(entry, `${path}[${index}]`));
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value)
      .filter(([key]) => !defaultVolatileField.test(`${path}.${key}`))
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, nested]) => [key, stable(nested, `${path}.${key}`)]),
  );
}

function paths(value: unknown, path = "$", output: string[] = []): string[] {
  if (Array.isArray(value)) {
    output.push(`${path}[]`);
    for (const entry of value.slice(0, 5)) paths(entry, `${path}[]`, output);
    return output;
  }
  if (value && typeof value === "object") {
    for (const [key, nested] of Object.entries(value)) {
      const next = `${path}.${key}`;
      output.push(next);
      paths(nested, next, output);
    }
  }
  return output;
}

function headerValue(headers: IncomingHttpHeaders, name: string): string {
  const value = headers[name];
  return Array.isArray(value) ? value.join(", ") : (value ?? "");
}

export function normalizeResponse(input: {
  statusCode: number;
  headers: IncomingHttpHeaders;
  body: Buffer;
  redirects: readonly string[];
  durationMs: number;
}): NormalizedResponse {
  const contentType =
    headerValue(input.headers, "content-type").split(";")[0]?.trim().toLowerCase() ?? "";
  const bodyText = input.body.toString("utf8");
  let parsed: unknown;
  let bodyKind: NormalizedResponse["bodyKind"] = input.body.length === 0 ? "EMPTY" : "TEXT";
  const firstBodyCharacter = bodyText.trimStart()[0];
  if (contentType.includes("json") || firstBodyCharacter === "{" || firstBodyCharacter === "[") {
    try {
      parsed = JSON.parse(bodyText);
      bodyKind = "JSON";
    } catch {
      bodyKind = contentType.startsWith("text/") ? "TEXT" : "BINARY";
    }
  } else if (!contentType.startsWith("text/") && input.body.length > 0) bodyKind = "BINARY";
  const fieldPaths = parsed === undefined ? [] : [...new Set(paths(parsed))].sort();
  const sensitiveFieldPaths = fieldPaths.filter((path) => defaultSensitiveField.test(path));
  const normalized =
    parsed === undefined
      ? bodyText
          .replace(/\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\b/gu, "<timestamp>")
          .replace(/\b[0-9a-f]{8}-[0-9a-f-]{27,}\b/giu, "<uuid>")
      : JSON.stringify(stable(parsed));
  const selectedHeaders: Record<string, string> = Object.fromEntries(
    Object.entries(
      redactHeaders(input.headers as Readonly<Record<string, string | string[] | undefined>>),
    )
      .filter(([name]) => selectedResponseHeaders.has(name.toLowerCase()))
      .map(([name, value]) => [
        name.toLowerCase(),
        Array.isArray(value) ? value.join(", ") : String(value),
      ]),
  );
  const errorShape =
    parsed && typeof parsed === "object"
      ? ["error", "message", "code", "status"]
          .filter((key) => key in (parsed as Record<string, unknown>))
          .sort()
          .join(",") || null
      : null;
  return {
    statusCode: input.statusCode,
    contentType,
    redirectLocation: headerValue(input.headers, "location") || null,
    redirectChain: [...input.redirects],
    bodyKind,
    bodyHash: createHash("sha256").update(input.body).digest("hex"),
    bodyLength: input.body.length,
    normalizedBodyHash: createHash("sha256").update(normalized).digest("hex"),
    jsonFieldPaths: fieldPaths,
    sensitiveFieldPaths,
    errorShape,
    selectedHeaders,
    redactedExcerpt: redactText(
      parsed === undefined ? bodyText : JSON.stringify(redactUnknown(parsed)),
    ).slice(0, 2_048),
    timingMs: input.durationMs,
  };
}

function jaccard(left: readonly string[], right: readonly string[]): number {
  const a = new Set(left);
  const b = new Set(right);
  const union = new Set([...a, ...b]);
  if (union.size === 0) return 1;
  return [...a].filter((value) => b.has(value)).length / union.size;
}

function confidenceLabel(score: number): AuthorizationDifference["confidenceLabel"] {
  if (score >= 0.9) return "CRITICAL-CONFIDENCE";
  if (score >= 0.7) return "HIGH";
  if (score >= 0.5) return "MEDIUM";
  if (score >= 0.3) return "LOW";
  return "INFO";
}

export function compareAuthorizationResponses(input: {
  baseline: AuthorizationObservation;
  comparison: AuthorizationObservation;
  relationship: AuthorizationDifference["relationship"];
  reproducible?: boolean;
}): AuthorizationDifference {
  const { baseline, comparison, relationship } = input;
  const structuralSimilarity = jaccard(
    baseline.response.jsonFieldPaths,
    comparison.response.jsonFieldPaths,
  );
  const comparisonSensitive = new Set(comparison.response.sensitiveFieldPaths);
  const sensitiveFieldOverlap = baseline.response.sensitiveFieldPaths.filter((path) =>
    comparisonSensitive.has(path),
  );
  const statusEquivalent = baseline.response.statusCode === comparison.response.statusCode;
  const redirectEquivalent =
    baseline.response.redirectLocation === comparison.response.redirectLocation;
  const contentTypeEquivalent = baseline.response.contentType === comparison.response.contentType;
  const expectedViolation = comparison.expected === "DENY" && comparison.response.statusCode < 400;
  const likelyEquivalent = statusEquivalent && structuralSimilarity >= 0.85;
  const authValid = ![baseline.authenticationState, comparison.authenticationState].some((state) =>
    ["AUTH_EXPIRED", "AUTH_FAILED", "UNAVAILABLE", "LOGGED_OUT"].includes(state),
  );
  const reasons: string[] = [];
  let classification: AuthorizationDifference["classification"] = "INCONCLUSIVE";
  let confidence = 0.15;
  let severity: AuthorizationDifference["severity"] = "INFO";

  if (!authValid) reasons.push("Comparison identity was not in a valid authenticated state.");
  if (expectedViolation) {
    confidence += 0.35;
    reasons.push("Observed behavior violates the operator-defined DENY policy.");
  }
  if (likelyEquivalent) {
    confidence += 0.2;
    reasons.push(
      "Status and normalized response structure are equivalent to the authorized baseline.",
    );
  }
  if (sensitiveFieldOverlap.length > 0) {
    confidence += 0.15;
    reasons.push("Sensitive field paths overlap without retaining their values.");
  }
  if (input.reproducible) {
    confidence += 0.1;
    reasons.push("The behavior was reproduced with bounded repeated samples.");
  }
  if (!redirectEquivalent) reasons.push("Redirect behavior differs between identities.");
  if (authValid && expectedViolation && likelyEquivalent) {
    if (relationship === "CROSS_TENANT") {
      classification = "POTENTIAL_TENANT_BYPASS";
      severity = sensitiveFieldOverlap.length > 0 ? "HIGH" : "MEDIUM";
    } else if (relationship === "SAME_ROLE_NON_OWNER") {
      classification = "POTENTIAL_HORIZONTAL_BYPASS";
      severity = sensitiveFieldOverlap.length > 0 ? "HIGH" : "MEDIUM";
    } else if (relationship === "LOWER_ROLE") {
      classification = "POTENTIAL_VERTICAL_BYPASS";
      severity = "HIGH";
    } else if (relationship === "ANONYMOUS") {
      classification = "AUTHENTICATION_INCONSISTENCY";
      severity = sensitiveFieldOverlap.length > 0 ? "HIGH" : "MEDIUM";
    }
  } else if (comparison.expected === "ALLOW" && comparison.response.statusCode < 400) {
    classification = "EXPECTED_ALLOW";
    confidence = Math.max(confidence, 0.8);
  } else if (comparison.expected === "DENY" && comparison.response.statusCode >= 400) {
    classification = "EXPECTED_DENY";
    confidence = Math.max(confidence, 0.8);
  }
  confidence = Math.min(1, Math.max(0, Number(confidence.toFixed(2))));
  return {
    baselineIdentityId: baseline.identityId,
    comparisonIdentityId: comparison.identityId,
    relationship,
    statusEquivalent,
    structuralSimilarity: Number(structuralSimilarity.toFixed(3)),
    sensitiveFieldOverlap,
    redirectEquivalent,
    contentTypeEquivalent,
    timingMedianDeltaMs:
      input.reproducible === true
        ? Number(Math.abs(baseline.response.timingMs - comparison.response.timingMs).toFixed(2))
        : null,
    classification,
    severity,
    confidence,
    confidenceLabel: confidenceLabel(confidence),
    reasons,
  };
}
