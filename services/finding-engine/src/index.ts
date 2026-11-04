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
  FORM_CSRF_PROTECTION_NOT_OBSERVED: {
    title: "Anti-CSRF control not observed in state-changing form",
    category: "CSRF_PROTECTION",
    severity: "LOW",
    confidence: 0.48,
    cwe: ["CWE-352"],
    owasp: ["A01:2021-Broken Access Control"],
    description:
      "A state-changing HTML form did not contain a field name recognizable as an anti-CSRF token. This passive observation cannot determine whether Origin, Referer, custom-header, or server-side controls provide equivalent protection.",
    technicalImpact:
      "If the action relies on ambient credentials and no compensating request-origin control exists, another origin may be able to induce an unwanted request.",
    businessImpact:
      "An affected authenticated workflow could permit unintended account or data changes in a victim's session.",
    remediation:
      "Verify the endpoint's complete CSRF defense. Use an unpredictable server-validated token for browser form submissions, validate request origin where appropriate, and apply suitable SameSite cookie policy.",
    manualVerificationRequired: true,
  },
  INPUT_REFLECTION_OBSERVED: {
    title: "Untrusted query input reflected in response",
    category: "INPUT_REFLECTION",
    severity: "LOW",
    confidence: 0.52,
    cwe: ["CWE-79", "CWE-116"],
    owasp: ["A03:2021-Injection"],
    description:
      "An inert, non-executable marker supplied through a query parameter was returned in the response. Reflection alone does not prove cross-site scripting or unsafe output encoding.",
    technicalImpact:
      "If the value reaches an executable browser context without context-appropriate encoding, an attacker-controlled URL may influence client-side content or script behavior.",
    businessImpact:
      "A separately confirmed script-injection path could affect users who follow a crafted link, including account actions or disclosure of browser-accessible data.",
    remediation:
      "Apply context-specific output encoding, avoid unsafe HTML or script construction, validate expected input types, and verify the reflected context through authorized manual testing.",
    manualVerificationRequired: true,
  },
  OPEN_REDIRECT_CONFIRMED: {
    title: "External open redirect observed",
    category: "OPEN_REDIRECT",
    severity: "MEDIUM",
    confidence: 0.96,
    cwe: ["CWE-601"],
    owasp: ["A01:2021-Broken Access Control"],
    description:
      "A navigation parameter accepted a harmless external destination and the response returned that destination in its Location header. The scanner did not follow the external redirect.",
    technicalImpact:
      "Trusted application links can redirect users to an attacker-controlled origin, enabling convincing phishing chains and potentially weakening OAuth or authentication flows when the same handler is reused.",
    businessImpact:
      "Users may trust a branded link that ultimately sends them to a fraudulent destination, increasing credential-theft and reputation risk.",
    remediation:
      "Use server-side identifiers or an exact allowlist of permitted destinations. Resolve and canonicalize relative paths, reject absolute untrusted URLs, and bind OAuth redirect URIs exactly.",
    discriminatorMetadataKey: "probeDestination",
  },
  CLIENT_SECRET_PATTERN_OBSERVED: {
    title: "Probable secret material embedded in client-side code",
    category: "CLIENT_SIDE_SECRET_EXPOSURE",
    severity: "MEDIUM",
    confidence: 0.74,
    cwe: ["CWE-798", "CWE-200"],
    owasp: ["A07:2021-Identification and Authentication Failures"],
    description:
      "A client-side resource contained text matching a high-specificity secret format. The value was redacted immediately and was not retained in finding evidence.",
    technicalImpact:
      "Any credential delivered to a browser must be considered publicly retrievable. Practical impact depends on whether the value is active and what permissions it grants.",
    businessImpact:
      "An active privileged credential could permit unauthorized use of a third-party service, data access, or unexpected service cost.",
    remediation:
      "Revoke and rotate the suspected credential, inspect its use logs, remove it from client artifacts and history, and move privileged operations behind an authenticated server-side boundary.",
    manualVerificationRequired: true,
    discriminatorMetadataKey: "secretType",
  },
  MIXED_CONTENT_REFERENCE_OBSERVED: {
    title: "HTTPS page references an insecure HTTP resource",
    category: "MIXED_CONTENT",
    severity: "LOW",
    confidence: 0.9,
    cwe: ["CWE-319"],
    owasp: ["A02:2021-Cryptographic Failures"],
    description: "An HTTPS document contained an explicit HTTP resource reference.",
    technicalImpact:
      "Depending on resource type and browser behavior, the resource may be blocked or exposed to network modification, weakening transport integrity.",
    businessImpact:
      "Broken resources or modifiable passive content can reduce user trust and may create a path to content manipulation.",
    remediation:
      "Serve every page dependency over HTTPS, replace explicit HTTP URLs, and use Content-Security-Policy upgrade-insecure-requests only as defense in depth.",
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
  POTENTIAL_HORIZONTAL_AUTHORIZATION_FAILURE: {
    title: "Potential horizontal object-authorization failure",
    category: "BROKEN_OBJECT_LEVEL_AUTHORIZATION",
    severity: "HIGH",
    confidence: 0.7,
    cwe: ["CWE-639"],
    owasp: ["A01:2021-Broken Access Control", "API1:2023-Broken Object Level Authorization"],
    description:
      "A same-role non-owner identity received behavior structurally equivalent to the approved owner baseline despite an explicit DENY policy.",
    technicalImpact:
      "A user may be able to access an object owned by another authorized test identity at the same privilege level.",
    businessImpact:
      "Horizontal access-control failure can expose or permit actions on another user's records within the tested boundary.",
    remediation:
      "Enforce object ownership or explicit sharing authorization server-side on every object operation, derive the caller from the authenticated session, and add owner/non-owner regression tests.",
    discriminatorMetadataKey: "groupedFindingFingerprint",
  },
  POTENTIAL_VERTICAL_AUTHORIZATION_FAILURE: {
    title: "Potential vertical function-authorization failure",
    category: "BROKEN_FUNCTION_LEVEL_AUTHORIZATION",
    severity: "HIGH",
    confidence: 0.7,
    cwe: ["CWE-862"],
    owasp: ["A01:2021-Broken Access Control", "API5:2023-Broken Function Level Authorization"],
    description:
      "A lower-privileged identity received behavior structurally equivalent to the higher-privileged baseline despite an explicit DENY policy.",
    technicalImpact:
      "A lower-privileged account may invoke functionality reserved for a more privileged role.",
    businessImpact:
      "Role-boundary failure can permit unauthorized administrative or management actions in the affected workflow.",
    remediation:
      "Centralize server-side role and permission checks at the operation boundary, deny by default, and add lower-role versus privileged-role regression tests.",
    discriminatorMetadataKey: "groupedFindingFingerprint",
  },
  POTENTIAL_TENANT_ISOLATION_FAILURE: {
    title: "Potential cross-tenant authorization failure",
    category: "TENANT_ISOLATION",
    severity: "HIGH",
    confidence: 0.72,
    cwe: ["CWE-639"],
    owasp: ["A01:2021-Broken Access Control", "API1:2023-Broken Object Level Authorization"],
    description:
      "An identity belonging to another configured tenant received behavior structurally equivalent to the authorized tenant baseline despite an explicit DENY policy.",
    technicalImpact:
      "Tenant scoping may not be consistently applied when resolving or authorizing the affected resource.",
    businessImpact:
      "Cross-tenant isolation failure can expose client data across organizational boundaries.",
    remediation:
      "Bind every resource query and authorization decision to the authenticated tenant, reject caller-supplied tenant authority, and add cross-tenant negative tests.",
    discriminatorMetadataKey: "groupedFindingFingerprint",
  },
  AUTHENTICATION_STATE_INCONSISTENCY: {
    title: "Potential unauthenticated access inconsistency",
    category: "AUTHENTICATION_ENFORCEMENT",
    severity: "HIGH",
    confidence: 0.7,
    cwe: ["CWE-306"],
    owasp: ["A07:2021-Identification and Authentication Failures"],
    description:
      "The isolated anonymous identity received behavior structurally equivalent to an authenticated baseline despite an explicit DENY policy.",
    technicalImpact:
      "The endpoint may expose authenticated behavior without a valid authenticated session.",
    businessImpact:
      "Unauthenticated access may expose account or business data to arbitrary external users.",
    remediation:
      "Require authentication at the server-side route boundary, fail closed when session validation fails, and add anonymous negative regression tests.",
    discriminatorMetadataKey: "groupedFindingFingerprint",
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
  const observedConfidence = metadata["confidence"];
  const confidence =
    typeof observedConfidence === "number" && observedConfidence >= 0 && observedConfidence <= 1
      ? observedConfidence
      : definition.confidence;
  const manualVerificationRequired = definition.manualVerificationRequired ?? false;
  const base = canonicalFindingSchema.parse({
    title: definition.title,
    category: definition.category,
    severity,
    confidence: Math.min(0.99, confidence + Math.min(0.03, evidenceIds.length * 0.01)),
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
