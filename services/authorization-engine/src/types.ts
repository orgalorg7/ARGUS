import type { ScopedResponse } from "@aasp/scope-engine";

export type AuthenticationType =
  | "ANONYMOUS"
  | "USERNAME_PASSWORD"
  | "SESSION_COOKIE"
  | "BEARER_TOKEN"
  | "API_KEY"
  | "CUSTOM_HEADERS"
  | "OAUTH_OIDC"
  | "LOGIN_AUTOMATION";

export type AuthenticationState =
  | "AUTHENTICATED"
  | "AUTH_EXPIRED"
  | "AUTH_REFRESHING"
  | "AUTH_FAILED"
  | "LOGGED_OUT"
  | "UNKNOWN"
  | "UNAVAILABLE";

export interface AssessmentIdentity {
  id: string;
  label: string;
  role: string;
  tenant: string | null;
  authenticationType: AuthenticationType;
  credentialReference: string | null;
  authenticationState: AuthenticationState;
  metadata: Readonly<Record<string, unknown>>;
  enabled: boolean;
}

export type CredentialMaterial =
  | { type: "ANONYMOUS" }
  | { type: "USERNAME_PASSWORD"; username: string; password: string }
  | { type: "SESSION_COOKIE"; name: string; value: string; domain?: string; path?: string }
  | { type: "BEARER_TOKEN"; token: string }
  | { type: "API_KEY"; headerName: string; value: string }
  | { type: "CUSTOM_HEADERS"; headers: Readonly<Record<string, string>> }
  | { type: "OAUTH_OIDC"; adapterConfig: Readonly<Record<string, unknown>> }
  | { type: "LOGIN_AUTOMATION"; adapterConfig: Readonly<Record<string, unknown>> };

export type ResourceProvenance =
  | "OPERATOR_SUPPLIED"
  | "SCANNER_CREATED"
  | "APPROVED_SEED"
  | "IDENTITY_OBSERVED";

export type ResourceRelationship =
  | "OWNS"
  | "MEMBER_OF"
  | "ADMIN_OF"
  | "MANAGER_OF"
  | "BELONGS_TO_TENANT"
  | "SHARED_WITH";

export interface AuthorizedResource {
  id: string;
  type: string;
  externalId: string;
  tenant: string | null;
  ownerIdentityId: string | null;
  provenance: ResourceProvenance;
  endpointVariables: Readonly<Record<string, string>>;
  metadata: Readonly<Record<string, unknown>>;
}

export interface OwnershipEdge {
  identityId: string;
  resourceId: string;
  relationship: ResourceRelationship;
}

export type ExpectedAuthorization = "ALLOW" | "DENY" | "UNKNOWN";
export type MutationRisk = "READ_ONLY" | "SAFE_IDEMPOTENT" | "DISPOSABLE_TEST_FIXTURE";
export type CleanupStrategy = "NONE" | "DELETE_CREATED_RESOURCE" | "RESTORE_FIXTURE" | "CUSTOM";
export type HttpMethod = "GET" | "HEAD" | "OPTIONS" | "POST" | "PUT" | "PATCH" | "DELETE";

export interface AuthorizationTestCase {
  id: string;
  name: string;
  resourceId: string;
  action: string;
  endpointTemplate: string;
  method: HttpMethod;
  identityIds: readonly string[];
  expectedPolicy: Readonly<Record<string, ExpectedAuthorization>>;
  mutationRisk: MutationRisk;
  mutationExplicitlyAuthorized: boolean;
  cleanupStrategy: CleanupStrategy;
  requestHeaders: Readonly<Record<string, string>>;
  requestBody?: string;
  contentType?: string;
  followRedirects: boolean;
  timingSamples: number;
}

export interface NormalizedResponse {
  statusCode: number;
  contentType: string;
  redirectLocation: string | null;
  redirectChain: readonly string[];
  bodyKind: "JSON" | "TEXT" | "EMPTY" | "BINARY";
  bodyHash: string;
  bodyLength: number;
  normalizedBodyHash: string;
  jsonFieldPaths: readonly string[];
  sensitiveFieldPaths: readonly string[];
  errorShape: string | null;
  selectedHeaders: Readonly<Record<string, string>>;
  redactedExcerpt: string;
  timingMs: number;
}

export interface AuthorizationObservation {
  identityId: string;
  identityLabel: string;
  identityRole: string;
  identityTenant: string | null;
  authenticationState: AuthenticationState;
  expected: ExpectedAuthorization;
  requestedUrl: string;
  response: NormalizedResponse;
  evidenceFingerprint: string;
  error: string | null;
  reproducible?: boolean;
}

export interface AuthorizationDifference {
  baselineIdentityId: string;
  comparisonIdentityId: string;
  relationship:
    | "OWNER"
    | "SAME_ROLE_NON_OWNER"
    | "HIGHER_ROLE"
    | "LOWER_ROLE"
    | "CROSS_TENANT"
    | "ANONYMOUS"
    | "OTHER";
  statusEquivalent: boolean;
  structuralSimilarity: number;
  sensitiveFieldOverlap: readonly string[];
  redirectEquivalent: boolean;
  contentTypeEquivalent: boolean;
  timingMedianDeltaMs: number | null;
  classification:
    | "EXPECTED_ALLOW"
    | "EXPECTED_DENY"
    | "POTENTIAL_HORIZONTAL_BYPASS"
    | "POTENTIAL_VERTICAL_BYPASS"
    | "POTENTIAL_TENANT_BYPASS"
    | "AUTHENTICATION_INCONSISTENCY"
    | "INCONCLUSIVE";
  severity: "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  confidence: number;
  confidenceLabel: "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL-CONFIDENCE";
  reasons: readonly string[];
}

export interface AuthorizationMatrixResult {
  testCaseId: string;
  correlationId: string;
  resource: AuthorizedResource;
  observations: readonly AuthorizationObservation[];
  differences: readonly AuthorizationDifference[];
  incompleteIdentityIds: readonly string[];
  startedAt: string;
  completedAt: string;
}

export interface AuthorizationTransportRequest {
  url: string;
  method: HttpMethod;
  headers: Readonly<Record<string, string>>;
  body?: string;
  timeoutMs: number;
  followRedirects: boolean;
  signal?: AbortSignal;
}

export interface AuthorizationTransportResponse {
  response: ScopedResponse;
  durationMs: number;
}

export interface AuthorizationTransport {
  request(input: AuthorizationTransportRequest): Promise<AuthorizationTransportResponse>;
}
