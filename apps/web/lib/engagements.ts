export interface ClientRecord {
  id: string;
  name: string;
  legalName: string;
}
export interface EngagementRecord {
  id: string;
  name: string;
  objective: string;
  environment: string;
  state: string;
  version: number;
  policyRevision: number;
  requestsMade: number;
  client: ClientRecord;
}
export interface PolicyRecord {
  revision: number;
  windowStartsAt: string;
  windowEndsAt: string;
  maxRequests: number;
  requestsPerSecond: number;
  maxConcurrency: number;
  maxRisk: string;
  allowedCategories: string[];
  allowedProtocols: string[];
  restrictions: string;
  targets: Array<{
    scopeRevision: number;
    scopeDigest: string;
    target: { id: string; name: string; origin: string; scopeRevision: number; status: string };
  }>;
}
export interface EngagementDetail extends EngagementRecord {
  policies: PolicyRecord[];
  documents: Array<{ id: string; filename: string; sha256: string; createdAt: string }>;
  grants: Array<{
    id: string;
    policyRevision: number;
    authorizedBy: string;
    validFrom: string;
    validUntil: string;
    revocation: { reason: string } | null;
  }>;
  transitions: Array<{
    id: string;
    toState: string;
    reason: string;
    createdAt: string;
    authorizationBasis: string;
  }>;
  scans: Array<{ id: string; name: string; state: string }>;
  allowedTransitions: string[];
  canManage: boolean;
  canAuthorize: boolean;
  canReadDocuments: boolean;
  canExecute: boolean;
}
export interface PageResult<T> {
  items: T[];
  nextCursor: string | null;
}
