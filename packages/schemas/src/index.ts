import { z } from "zod";

export const workspaceRoleSchema = z.enum(["OWNER", "ADMIN", "ANALYST", "VIEWER"]);
export type WorkspaceRole = z.infer<typeof workspaceRoleSchema>;

export const targetStatusSchema = z.enum([
  "DRAFT",
  "READY",
  "SCANNING",
  "COMPLETED",
  "FAILED",
  "CANCELLED",
  "DISABLED",
]);
export type TargetStatus = z.infer<typeof targetStatusSchema>;

export const targetScopeSchema = z
  .object({
    allowedDomains: z.array(z.string().trim().min(1).max(253)).min(1).max(50),
    includeSubdomains: z.boolean(),
    allowedPorts: z.array(z.number().int().min(1).max(65_535)).min(1).max(32),
    excludedPaths: z.array(z.string().trim().min(1).max(2_048)).max(200),
    allowPrivateNetwork: z.boolean().default(false),
  })
  .strict();
export type TargetScopeInput = z.infer<typeof targetScopeSchema>;

export const scanProfileSchema = z.enum(["LIGHT", "STANDARD", "DEEP_SAFE"]);
export type ScanProfile = z.infer<typeof scanProfileSchema>;

export const scanStateSchema = z.enum([
  "CREATED",
  "AUTHORIZED",
  "QUEUED",
  "VALIDATING_SCOPE",
  "DISCOVERY",
  "CRAWLING",
  "API_DISCOVERY",
  "FINGERPRINTING",
  "PASSIVE_ANALYSIS",
  "SAFE_ACTIVE_ANALYSIS",
  "NORMALIZING",
  "CORRELATING",
  "AI_ANALYSIS",
  "AI_ANALYSIS_WAITING_FOR_PROVIDER",
  "GENERATING_SCAN_REPORT",
  "GENERATING_VULNERABILITY_REPORTS",
  "COMPLETED",
  "COMPLETED_WITH_WARNINGS",
  "FAILED",
  "CANCELLED",
]);
export type ScanState = z.infer<typeof scanStateSchema>;

export const severitySchema = z.enum(["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]);
export type Severity = z.infer<typeof severitySchema>;

export const scanConfigSchema = z
  .object({
    crawlDepth: z.number().int().min(0).max(10),
    maxUrls: z.number().int().min(1).max(10_000),
    maxRequests: z.number().int().min(1).max(50_000),
    requestsPerSecond: z.number().positive().max(20),
    concurrency: z.number().int().min(1).max(20),
    timeoutMs: z.number().int().min(500).max(60_000),
    followRedirects: z.boolean(),
    includeSubdomains: z.boolean(),
    scanProfile: scanProfileSchema,
  })
  .strict();
export type ScanConfigInput = z.infer<typeof scanConfigSchema>;

export const scanProfileDefaults: Record<ScanProfile, ScanConfigInput> = {
  LIGHT: {
    crawlDepth: 1,
    maxUrls: 50,
    maxRequests: 150,
    requestsPerSecond: 2,
    concurrency: 2,
    timeoutMs: 10_000,
    followRedirects: true,
    includeSubdomains: false,
    scanProfile: "LIGHT",
  },
  STANDARD: {
    crawlDepth: 3,
    maxUrls: 500,
    maxRequests: 2_000,
    requestsPerSecond: 5,
    concurrency: 5,
    timeoutMs: 15_000,
    followRedirects: true,
    includeSubdomains: false,
    scanProfile: "STANDARD",
  },
  DEEP_SAFE: {
    crawlDepth: 6,
    maxUrls: 2_500,
    maxRequests: 10_000,
    requestsPerSecond: 8,
    concurrency: 8,
    timeoutMs: 20_000,
    followRedirects: true,
    includeSubdomains: true,
    scanProfile: "DEEP_SAFE",
  },
};

export const evidenceSchema = z
  .object({
    id: z.string().min(1),
    workspaceId: z.string().min(1),
    scanId: z.string().min(1),
    timestamp: z.string().datetime(),
    source: z.string().min(1),
    asset: z.string().min(1),
    requestMetadata: z.record(z.string(), z.unknown()),
    responseMetadata: z.record(z.string(), z.unknown()),
    redactedExcerpt: z.string(),
    hash: z.string().regex(/^[a-f0-9]{64}$/),
  })
  .strict();

export const qwenAnalysisInputSchema = z
  .object({
    assessmentPolicy: z.record(z.string(), z.unknown()),
    targetMetadata: z.record(z.string(), z.unknown()),
    observation: z.record(z.string(), z.unknown()),
    evidence: z.array(evidenceSchema).min(1),
    knownContext: z.record(z.string(), z.unknown()),
  })
  .strict();

export const qwenAnalysisOutputSchema = z
  .object({
    title: z.string().min(1).max(240),
    classification: z.string().min(1).max(160),
    severity: severitySchema,
    confidence: z.number().min(0).max(1),
    cwe: z.array(z.string().regex(/^CWE-\d+$/)),
    owasp: z.array(z.string().min(1)),
    description: z.string().min(1),
    technicalImpact: z.string().min(1),
    businessImpact: z.string().min(1),
    reasoningSummary: z.string().min(1),
    remediation: z.string().min(1),
    likelyFalsePositive: z.boolean(),
    manualVerificationRequired: z.boolean(),
    evidenceIds: z.array(z.string().min(1)).min(1),
  })
  .strict();

export type QwenAnalysisInput = z.infer<typeof qwenAnalysisInputSchema>;
export type QwenAnalysisOutput = z.infer<typeof qwenAnalysisOutputSchema>;

export const canonicalFindingSchema = z
  .object({
    title: z.string().min(1).max(240),
    category: z.string().min(1).max(160),
    severity: severitySchema,
    confidence: z.number().min(0).max(1),
    status: z.enum([
      "OPEN",
      "ACCEPTED_RISK",
      "FALSE_POSITIVE",
      "REMEDIATED",
      "MANUAL_VERIFICATION_REQUIRED",
    ]),
    cwe: z.array(z.string().regex(/^CWE-\d+$/)).max(20),
    owasp: z.array(z.string().min(1).max(80)).max(20),
    asset: z.string().min(1),
    endpoint: z.string().nullable(),
    method: z.string().nullable(),
    parameter: z.string().nullable(),
    description: z.string().min(1).max(8_000),
    technicalImpact: z.string().min(1).max(8_000),
    businessImpact: z.string().min(1).max(8_000),
    evidenceIds: z.array(z.string().min(1)).min(1),
    scannerSources: z.array(z.string().min(1)).min(1),
    remediation: z.string().min(1).max(8_000),
    manualVerificationRequired: z.boolean(),
  })
  .strict();

export type CanonicalFinding = z.infer<typeof canonicalFindingSchema>;

export const scannerEvidenceInputSchema = z
  .object({
    source: z.string().min(1),
    asset: z.string().min(1),
    requestMetadata: z.record(z.string(), z.unknown()),
    responseMetadata: z.record(z.string(), z.unknown()),
    excerpt: z.string().max(65_536),
  })
  .strict();

export const scannerObservationInputSchema = z
  .object({
    scanner: z.string().min(1),
    scannerVersion: z.string().min(1),
    observationType: z.string().min(1),
    asset: z.string().min(1),
    endpoint: z.string().optional(),
    method: z.string().optional(),
    parameter: z.string().optional(),
    rawSeverity: z.string().optional(),
    evidence: z.array(scannerEvidenceInputSchema).min(1),
    metadata: z.record(z.string(), z.unknown()),
  })
  .strict();

export type ScannerEvidenceInput = z.infer<typeof scannerEvidenceInputSchema>;
export type ScannerObservationInput = z.infer<typeof scannerObservationInputSchema>;
