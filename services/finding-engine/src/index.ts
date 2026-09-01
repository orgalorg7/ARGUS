import { canonicalFindingSchema, type CanonicalFinding, type Severity } from "@aasp/schemas";

export interface FindingEvidenceRecord {
  id: string;
  timestamp: Date;
  source: string;
  asset: string;
  hash: string;
  requestMetadata: unknown;
  responseMetadata: unknown;
  redactedExcerpt: string;
}

export interface FindingObservationRecord {
  id: string;
  scanner: string;
  scannerVersion: string;
  observationType: string;
  asset: string;
  endpoint: string | null;
  method: string | null;
  parameter: string | null;
  rawSeverity: string | null;
  metadata: unknown;
  createdAt: Date;
  evidence: FindingEvidenceRecord[];
}

export interface NormalizedFindingCandidate extends CanonicalFinding {
  observationIds: string[];
  correlationDiscriminator: string | null;
  firstSeen: Date;
  lastSeen: Date;
}

interface FindingDefinition {
  title: string;
  category: string;
  severity: Severity;
  confidence: number;
  cwe: string[];
  owasp: string[];
  description: string;
  technicalImpact: string;
  businessImpact: string;
  remediation: string;
  manualVerificationRequired?: boolean;
  discriminatorMetadataKey?: string;
}

const definitions: Readonly<Record<string, FindingDefinition>> = {
  SERVER_TECHNOLOGY_DISCLOSURE: {
    title: "Server technology disclosure observed",
    category: "INFORMATION_DISCLOSURE",
    severity: "INFO",
    confidence: 0.96,
    cwe: ["CWE-200"],
    owasp: ["A05:2021-Security Misconfiguration"],
    description: "The response disclosed server or framework technology information.",
    technicalImpact:
      "Technology disclosure can improve an attacker's ability to select relevant techniques, but does not by itself prove an exploitable weakness.",
    businessImpact:
      "The disclosure marginally reduces uncertainty for an attacker and may increase exposure when the disclosed component is outdated.",
    remediation:
      "Remove unnecessary product and framework disclosure headers or configure them to omit version details.",
    discriminatorMetadataKey: "header",
  },
  SESSION_RESPONSE_CACHE_POLICY_WEAK: {
    title: "Session response cache policy is weak",
    category: "SESSION_CACHE_CONTROL",
    severity: "LOW",
    confidence: 0.82,
    cwe: ["CWE-524"],
    owasp: ["A05:2021-Security Misconfiguration"],
    description:
      "A response associated with a session-indicating cookie did not include an observable no-store or private cache directive.",
    technicalImpact:
      "Sensitive session-associated content may be retained by browser or intermediary caches depending on the surrounding response and cache behavior.",
    businessImpact:
      "Shared-device or intermediary cache exposure could disclose account-related information.",
    remediation:
      "Apply an appropriate Cache-Control policy, commonly no-store for sensitive authenticated responses, and verify intermediary behavior.",
    manualVerificationRequired: true,
  },
  CONTENT_SECURITY_POLICY_MISSING: {
    title: "Content Security Policy header not observed",
    category: "CONTENT_SECURITY_POLICY",
    severity: "LOW",
    confidence: 0.94,
    cwe: ["CWE-693"],
    owasp: ["A05:2021-Security Misconfiguration"],
    description: "Successful HTML responses did not include a Content-Security-Policy header.",
    technicalImpact:
      "The application lacks a browser-enforced defense-in-depth control that can limit the impact of script injection and unsafe resource loading.",
    businessImpact:
      "If a separate content injection weakness exists, the absence of CSP can increase its impact.",
    remediation:
      "Deploy a restrictive, application-specific Content-Security-Policy and introduce it in report-only mode before enforcement where necessary.",
  },
  NOSNIFF_HEADER_MISSING: {
    title: "MIME sniffing protection not observed",
    category: "MIME_SNIFFING_PROTECTION",
    severity: "LOW",
    confidence: 0.94,
    cwe: ["CWE-693"],
    owasp: ["A05:2021-Security Misconfiguration"],
    description: "Successful HTML responses did not include X-Content-Type-Options: nosniff.",
    technicalImpact:
      "Some user agents may infer a response type instead of honoring the declared content type, increasing risk when untrusted content is served.",
    businessImpact:
      "Content-type confusion may increase the impact of unsafe upload or content-hosting behavior elsewhere in the application.",
    remediation:
      "Set X-Content-Type-Options: nosniff and return accurate Content-Type values for all responses.",
  },
  FRAME_PROTECTION_MISSING: {
    title: "Frame embedding protection not observed",
    category: "CLICKJACKING_PROTECTION",
    severity: "LOW",
    confidence: 0.92,
    cwe: ["CWE-1021"],
    owasp: ["A05:2021-Security Misconfiguration"],
    description:
      "Successful HTML responses did not expose X-Frame-Options or a CSP frame-ancestors directive.",
    technicalImpact:
      "Pages may be embeddable by another origin, which can enable user-interface redressing when sensitive actions are present.",
    businessImpact:
      "Users could be induced to perform unintended actions if affected pages contain sensitive controls and lack compensating defenses.",
    remediation:
      "Define CSP frame-ancestors with the minimum required origins and optionally retain X-Frame-Options for legacy user agents.",
    manualVerificationRequired: true,
  },
  REFERRER_POLICY_MISSING: {
    title: "Referrer Policy header not observed",
    category: "REFERRER_INFORMATION_CONTROL",
    severity: "INFO",
    confidence: 0.9,
    cwe: ["CWE-200"],
    owasp: ["A05:2021-Security Misconfiguration"],
    description: "Successful HTML responses did not include an explicit Referrer-Policy header.",
    technicalImpact:
      "Browsers will apply their default referrer behavior instead of an application-selected data-minimizing policy.",
    businessImpact:
      "URL information may be disclosed to linked origins when sensitive values are placed in URLs.",
    remediation:
      "Set a suitable Referrer-Policy such as strict-origin-when-cross-origin and avoid placing secrets in URLs.",
  },
  PERMISSIONS_POLICY_MISSING: {
    title: "Permissions Policy header not observed",
    category: "BROWSER_CAPABILITY_CONTROL",
    severity: "INFO",
    confidence: 0.9,
    cwe: ["CWE-693"],
    owasp: ["A05:2021-Security Misconfiguration"],
    description: "Successful HTML responses did not include an explicit Permissions-Policy header.",
    technicalImpact: "Browser features are not explicitly constrained at the response boundary.",
    businessImpact:
      "The missing defense-in-depth control can increase exposure if untrusted embedded content is introduced.",
    remediation:
      "Define a Permissions-Policy that disables unused browser capabilities and grants required features only to intended origins.",
  },
  HSTS_HEADER_MISSING: {
    title: "HTTP Strict Transport Security not observed",
    category: "TRANSPORT_SECURITY_POLICY",
    severity: "LOW",
    confidence: 0.94,
    cwe: ["CWE-319"],
    owasp: ["A02:2021-Cryptographic Failures"],
    description: "An HTTPS response did not include Strict-Transport-Security.",
    technicalImpact:
      "A user's initial navigation may remain susceptible to protocol downgrade or insecure-link navigation on hostile networks.",
    businessImpact:
      "Session or application data could be exposed if a user is redirected to an insecure transport before HTTPS is established.",
    remediation:
      "After validating full HTTPS readiness, enable Strict-Transport-Security with an appropriate max-age and carefully assess subdomain coverage.",
  },
  COOKIE_SECURE_ATTRIBUTE_MISSING: {
    title: "Cookie missing Secure attribute",
    category: "COOKIE_TRANSPORT_SECURITY",
    severity: "LOW",
    confidence: 0.95,
    cwe: ["CWE-614"],
    owasp: ["A02:2021-Cryptographic Failures"],
    description: "A response set a cookie without the Secure attribute.",
    technicalImpact:
      "The browser may send the cookie over an unencrypted HTTP connection when such a path is reachable.",
    businessImpact:
      "Exposure of a sensitive cookie could contribute to account or session compromise.",
    remediation:
      "Set Secure on cookies that must only travel over HTTPS and ensure the application consistently redirects or rejects HTTP.",
    discriminatorMetadataKey: "cookieName",
  },
  SESSION_COOKIE_HTTPONLY_MISSING: {
    title: "Session-indicating cookie missing HttpOnly",
    category: "COOKIE_SCRIPT_ACCESS",
    severity: "MEDIUM",
    confidence: 0.96,
    cwe: ["CWE-1004"],
    owasp: ["A05:2021-Security Misconfiguration"],
    description: "A session-indicating cookie was set without the HttpOnly attribute.",
    technicalImpact:
      "Client-side scripts can access the cookie, increasing the impact of a separate script-injection vulnerability.",
    businessImpact:
      "A successful script-injection attack may be more capable of stealing session material and compromising accounts.",
    remediation:
      "Set HttpOnly on session cookies unless client-side access is strictly required, and maintain defenses against script injection.",
    discriminatorMetadataKey: "cookieName",
  },
  COOKIE_SAMESITE_WEAK_OR_MISSING: {
    title: "Cookie SameSite protection is weak or missing",
    category: "COOKIE_CROSS_SITE_CONTROL",
    severity: "MEDIUM",
    confidence: 0.9,
    cwe: ["CWE-1275"],
    owasp: ["A01:2021-Broken Access Control"],
    description: "A cookie was set without an effective SameSite restriction.",
    technicalImpact:
      "The browser may attach the cookie to cross-site requests, depending on cookie attributes and browser behavior.",
    businessImpact:
      "State-changing endpoints may have increased cross-site request exposure if separate anti-CSRF controls are absent.",
    remediation:
      "Use SameSite=Lax or Strict where compatible. Cookies requiring SameSite=None must also use Secure and should be protected by explicit anti-CSRF controls.",
    discriminatorMetadataKey: "cookieName",
    manualVerificationRequired: true,
  },
  CORS_ARBITRARY_ORIGIN_WITH_CREDENTIALS: {
    title: "Arbitrary CORS origin accepted with credentials",
    category: "CORS_MISCONFIGURATION",
    severity: "HIGH",
    confidence: 0.96,
    cwe: ["CWE-942"],
    owasp: ["A01:2021-Broken Access Control"],
    description:
      "A controlled untrusted Origin value was reflected in Access-Control-Allow-Origin while credentialed cross-origin requests were enabled.",
    technicalImpact:
      "A malicious origin may be able to read credentialed responses in a victim's browser when authentication cookies and endpoint behavior permit it.",
    businessImpact:
      "Affected authenticated data or actions may be exposed across origins, potentially resulting in account data disclosure.",
    remediation:
      "Use an exact allowlist of trusted origins, reject unrecognized origins, and enable credentialed CORS only for endpoints that require it.",
    manualVerificationRequired: true,
  },
  CORS_WILDCARD_WITH_CREDENTIALS: {
    title: "Inconsistent wildcard credentialed CORS policy observed",
    category: "CORS_MISCONFIGURATION",
    severity: "LOW",
    confidence: 0.88,
    cwe: ["CWE-942"],
    owasp: ["A05:2021-Security Misconfiguration"],
    description:
      "The response combined a wildcard Access-Control-Allow-Origin value with credential allowance.",
    technicalImpact:
      "Browsers normally reject this combination for credentialed reads, but it indicates an inconsistent CORS policy that should be reviewed.",
    businessImpact:
      "Policy inconsistency can lead to future exposure if origin handling changes or non-browser clients rely on the configuration.",
    remediation:
      "Do not combine wildcard origins with credential allowance. Use explicit trusted origins or disable credentials.",
  },
  SOURCE_MAP_PUBLICLY_ACCESSIBLE: {
    title: "Client source map publicly accessible",
    category: "SOURCE_CODE_INFORMATION_DISCLOSURE",
    severity: "LOW",
    confidence: 0.94,
    cwe: ["CWE-540"],
    owasp: ["A05:2021-Security Misconfiguration"],
    description: "A source-map resource was retrieved successfully and contained content.",
    technicalImpact:
      "Source maps may disclose readable client source, internal paths, comments, and implementation details.",
    businessImpact:
      "Exposed implementation detail can reduce attacker effort and may disclose proprietary client-side code.",
    remediation:
      "Exclude production source maps from public deployment or restrict access to authorized debugging workflows.",
  },
  VERBOSE_ERROR_DETAILS_OBSERVED: {
    title: "Verbose application error details disclosed",
    category: "VERBOSE_ERROR_DISCLOSURE",
    severity: "LOW",
    confidence: 0.94,
    cwe: ["CWE-209"],
    owasp: ["A05:2021-Security Misconfiguration"],
    description:
      "An error response exposed stack or exception details matching deterministic error markers.",
    technicalImpact:
      "Stack details may reveal internal file paths, frameworks, code structure, and failure behavior.",
    businessImpact:
      "Implementation disclosure can reduce attacker effort and may expose sensitive operational details.",
    remediation:
      "Return generic external error responses, retain detailed diagnostics only in access-controlled server logs, and remove debug modes from production.",
  },
};

function metadataRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function normalizeSeverity(value: string | null, fallback: Severity): Severity {
  const supported: Severity[] = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
  return supported.includes(value as Severity) ? (value as Severity) : fallback;
}

export function normalizeObservation(
  observation: FindingObservationRecord,
): NormalizedFindingCandidate | null {
  const definition = definitions[observation.observationType];
  if (!definition || observation.evidence.length === 0) return null;
  const evidenceIds = [...new Set(observation.evidence.map(({ id }) => id))];
  if (evidenceIds.length === 0) return null;
  const metadata = metadataRecord(observation.metadata);
  const discriminatorValue = definition.discriminatorMetadataKey
    ? metadata[definition.discriminatorMetadataKey]
    : null;
  const severity = normalizeSeverity(observation.rawSeverity, definition.severity);
  const manualVerificationRequired = definition.manualVerificationRequired ?? false;
  const base = canonicalFindingSchema.parse({
    title: definition.title,
    category: definition.category,
    severity,
    confidence: Math.min(0.99, definition.confidence + Math.min(0.03, evidenceIds.length * 0.01)),
    status: manualVerificationRequired ? "MANUAL_VERIFICATION_REQUIRED" : "OPEN",
    cwe: definition.cwe,
    owasp: definition.owasp,
    asset: observation.asset,
    endpoint: observation.endpoint,
    method: observation.method,
    parameter: observation.parameter,
    description: definition.description,
    technicalImpact: definition.technicalImpact,
    businessImpact: definition.businessImpact,
    evidenceIds,
    scannerSources: [observation.scanner],
    remediation: definition.remediation,
    manualVerificationRequired,
  });
  return {
    ...base,
    observationIds: [observation.id],
    correlationDiscriminator:
      typeof discriminatorValue === "string" && discriminatorValue.length > 0
        ? discriminatorValue
        : null,
    firstSeen: observation.createdAt,
    lastSeen: observation.createdAt,
  };
}

export function normalizeObservations(
  observations: readonly FindingObservationRecord[],
): NormalizedFindingCandidate[] {
  return observations
    .map(normalizeObservation)
    .filter((candidate): candidate is NormalizedFindingCandidate => candidate !== null);
}
