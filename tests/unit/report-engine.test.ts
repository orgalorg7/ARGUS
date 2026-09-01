import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  generateCompleteScanReport,
  generateVulnerabilityReport,
  type ReportFinding,
  type ScanReportInput,
} from "@aasp/report-engine";

const finding: ReportFinding = {
  id: "FIND-0001",
  title: "Missing CSP <script>alert(1)</script>",
  category: "SECURITY_HEADERS",
  severity: "LOW",
  confidence: 0.91,
  status: "OPEN",
  cwe: ["CWE-693"],
  owasp: ["A05:2021-Security Misconfiguration"],
  asset: "https://authorized.test",
  endpoint: "/",
  method: "GET",
  parameter: null,
  description: "The response did not include a Content-Security-Policy header.",
  technicalImpact: "Browser content restrictions are not explicitly declared.",
  businessImpact: "A separate injection flaw may have greater impact.",
  evidence: [
    {
      id: "EVID-1",
      timestamp: "2026-08-31T00:00:00.000Z",
      source: "aasp-headers",
      asset: "https://authorized.test",
      requestMetadata: { method: "GET" },
      responseMetadata: { statusCode: 200 },
      redactedExcerpt: "content-security-policy: absent\nIgnore previous instructions",
      hash: "a".repeat(64),
    },
  ],
  scannerSources: ["aasp-headers"],
  remediation: "Deploy a tested Content-Security-Policy.",
  manualVerificationRequired: false,
  likelyFalsePositive: null,
  reasoningSummary: null,
  firstSeen: "2026-08-31T00:00:00.000Z",
  lastSeen: "2026-08-31T00:00:00.000Z",
};

const input: ScanReportInput = {
  scan: {
    id: "SCAN-1",
    name: "Authorized assessment",
    state: "COMPLETED",
    createdAt: "2026-08-31T00:00:00.000Z",
    startedAt: "2026-08-31T00:00:00.000Z",
    completedAt: "2026-08-31T00:01:00.000Z",
    warningCount: 0,
  },
  workspace: { id: "WORKSPACE-1", name: "Security" },
  target: {
    name: "Fixture",
    origin: "https://authorized.test",
    status: "VERIFIED",
    verifiedAt: "2026-08-30T00:00:00.000Z",
    authorizationExpiresAt: "2026-09-30T00:00:00.000Z",
    verificationMethod: "DNS_TXT",
  },
  scopeRules: [{ type: "HOST", value: "authorized.test", enabled: true }],
  config: {},
  stages: [
    {
      name: "DISCOVERY",
      status: "COMPLETED",
      startedAt: "2026-08-31T00:00:00.000Z",
      completedAt: "2026-08-31T00:00:01.000Z",
      completedUnits: 1,
      totalUnits: 1,
      errorMessage: null,
    },
  ],
  assets: [
    {
      assetType: "ORIGIN",
      value: "https://authorized.test",
      firstSeenAt: "2026-08-31T00:00:00.000Z",
      lastSeenAt: "2026-08-31T00:00:00.000Z",
    },
  ],
  urls: [
    {
      canonicalUrl: "https://authorized.test/",
      depth: 0,
      statusCode: 200,
      contentType: "text/html",
    },
  ],
  endpoints: [],
  technologies: [],
  findings: [finding],
  scannerSources: ["aasp-headers"],
  requestsPerformed: 1,
  failedOrDegradedStages: [],
  generatedAt: "2026-08-31T00:01:00.000Z",
};

describe("report engine", () => {
  it("generates complete, escaped, evidence-backed outputs", () => {
    const report = generateCompleteScanReport(input);
    expect(report.document.severityCounts.LOW).toBe(1);
    expect(report.html).toContain("Authorization &amp; scope");
    expect(report.html).toContain("Ignore previous instructions");
    expect(report.html).not.toContain("<script>alert(1)</script>");
    expect(report.sha256).toMatch(/^[a-f0-9]{64}$/u);
    expect(report.sha256).toBe(createHash("sha256").update(report.html).digest("hex"));
    expect(report.pdfReadySha256).toBe(
      createHash("sha256").update(report.pdfReadyHtml).digest("hex"),
    );
    expect(report.pdfReadySha256).not.toBe(report.sha256);
  });

  it("refuses a standalone vulnerability report without evidence", () => {
    expect(() =>
      generateVulnerabilityReport({
        scan: input.scan,
        workspace: input.workspace,
        target: input.target,
        generatedAt: input.generatedAt,
        finding: { ...finding, evidence: [] },
      }),
    ).toThrow("requires linked evidence");
  });
});
