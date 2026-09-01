import { describe, expect, it } from "vitest";
import { correlateFindings } from "@aasp/correlation-engine";
import {
  normalizeObservation,
  normalizeObservations,
  type FindingObservationRecord,
} from "@aasp/finding-engine";

function observation(overrides: Partial<FindingObservationRecord> = {}): FindingObservationRecord {
  return {
    id: "obs-1",
    scanner: "aasp-headers",
    scannerVersion: "0.1.0",
    observationType: "CONTENT_SECURITY_POLICY_MISSING",
    asset: "https://fixture.test",
    endpoint: "/one",
    method: "GET",
    parameter: null,
    rawSeverity: "LOW",
    metadata: { missingHeader: "content-security-policy" },
    createdAt: new Date("2026-08-31T10:00:00.000Z"),
    evidence: [
      {
        id: "evidence-1",
        timestamp: new Date("2026-08-31T10:00:00.000Z"),
        source: "aasp-headers",
        asset: "https://fixture.test/one",
        hash: "a".repeat(64),
        requestMetadata: { method: "GET" },
        responseMetadata: { statusCode: 200 },
        redactedExcerpt: "content-security-policy: not observed",
      },
    ],
    ...overrides,
  };
}

describe("finding normalization and correlation", () => {
  it("never creates a finding without persisted evidence", () => {
    expect(normalizeObservation(observation({ evidence: [] }))).toBeNull();
  });

  it("ignores inventory observations that are not security findings", () => {
    expect(
      normalizeObservation(observation({ observationType: "HTTP_RESPONSE_PROFILE" })),
    ).toBeNull();
  });

  it("maps a deterministic observation to contextual severity and standards", () => {
    expect(normalizeObservation(observation())).toMatchObject({
      category: "CONTENT_SECURITY_POLICY",
      severity: "LOW",
      cwe: ["CWE-693"],
      manualVerificationRequired: false,
      evidenceIds: ["evidence-1"],
    });
  });

  it("deduplicates site-wide header observations without discarding evidence", () => {
    const candidates = normalizeObservations([
      observation(),
      observation({
        id: "obs-2",
        endpoint: "/two",
        createdAt: new Date("2026-08-31T10:01:00.000Z"),
        evidence: [
          {
            ...observation().evidence[0]!,
            id: "evidence-2",
            asset: "https://fixture.test/two",
            hash: "b".repeat(64),
          },
        ],
      }),
    ]);
    const correlated = correlateFindings(candidates);
    expect(correlated).toHaveLength(1);
    expect(correlated[0]?.evidenceIds).toEqual(["evidence-1", "evidence-2"]);
    expect(correlated[0]?.observationIds).toEqual(["obs-1", "obs-2"]);
  });

  it("keeps endpoint-specific CORS findings separate", () => {
    const first = observation({
      observationType: "CORS_ARBITRARY_ORIGIN_WITH_CREDENTIALS",
      scanner: "aasp-cors",
      rawSeverity: "HIGH",
    });
    const second = observation({
      id: "obs-2",
      observationType: "CORS_ARBITRARY_ORIGIN_WITH_CREDENTIALS",
      scanner: "aasp-cors",
      endpoint: "/two",
      rawSeverity: "HIGH",
      evidence: [{ ...observation().evidence[0]!, id: "evidence-2" }],
    });
    expect(correlateFindings(normalizeObservations([first, second]))).toHaveLength(2);
  });
});
