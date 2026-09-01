import { createHash } from "node:crypto";

const sensitiveHeaderPattern = /^(authorization|cookie|set-cookie|proxy-authorization|x-api-key)$/i;
const secretFieldPattern =
  /(authorization|cookie|password|passwd|secret|token|api[-_]?key|session|credential)/i;
const nonSecretPolicyFieldPattern =
  /^(access-control-allow-credentials|accessControlAllowCredentials|allowCredentials)$/i;
const bearerPattern = /\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi;
const jwtPattern = /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g;

/**
 * PostgreSQL text and JSONB reject U+0000. Other non-printing C0 controls are
 * removed as well so target-controlled excerpts cannot corrupt terminals or
 * downstream report renderers. Newlines, carriage returns, and tabs remain
 * intact because they carry useful HTTP evidence structure.
 */
export function sanitizeTextForPersistence(input: string): string {
  let sanitized = "";
  for (const character of input) {
    const codePoint = character.codePointAt(0) ?? 0;
    const isUnsafeC0 = codePoint < 32 && codePoint !== 9 && codePoint !== 10 && codePoint !== 13;
    if (!isUnsafeC0 && codePoint !== 127) sanitized += character;
  }
  return sanitized;
}

export function redactHeaders(
  headers: Readonly<Record<string, string | string[] | undefined>>,
): Record<string, string | string[]> {
  return Object.fromEntries(
    Object.entries(headers)
      .filter((entry): entry is [string, string | string[]] => entry[1] !== undefined)
      .map(([name, value]) => [name, sensitiveHeaderPattern.test(name) ? "[REDACTED]" : value]),
  );
}

export function redactText(input: string): string {
  return sanitizeTextForPersistence(input)
    .replace(bearerPattern, "$1 [REDACTED]")
    .replace(jwtPattern, "[REDACTED_JWT]")
    .replace(
      /(["']?(?:password|secret|token|api[-_]?key|session)["']?\s*[:=]\s*)["']?[^\s,"'&}]+/gi,
      "$1[REDACTED]",
    );
}

export function redactUnknown(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactUnknown);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, nested]) => [
        key,
        secretFieldPattern.test(key) && !nonSecretPolicyFieldPattern.test(key)
          ? "[REDACTED]"
          : redactUnknown(nested),
      ]),
    );
  }
  return typeof value === "string" ? redactText(value) : value;
}

export function evidenceHash(value: unknown): string {
  const serialized = typeof value === "string" ? value : JSON.stringify(value);
  return createHash("sha256").update(serialized).digest("hex");
}
