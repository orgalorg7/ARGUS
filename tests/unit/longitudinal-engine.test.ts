import { describe, expect, it } from "vitest";
import {
  compareAssessments,
  prioritizeFinding,
  type AssessmentSnapshot,
  type ComparableFinding,
} from "@aasp/longitudinal-engine";

function finding(
  correlationKey: string,
  overrides: Partial<ComparableFinding> = {},
): ComparableFinding {
  return {
    id: `finding-${correlationKey}`,
    correlationKey,
    severity: "MEDIUM",
    confidence: 0.8,
    category: "INPUT_VALIDATION",
    asset: "https://fixture.test",
    endpoint: `/${correlationKey}`,
    recurrenceCount: 1,
    ...overrides,
  };
}

function snapshot(
  scanId: string,
  findings: ComparableFinding[],
  overrides: Partial<AssessmentSnapshot> = {},
): AssessmentSnapshot {
  return {
    scanId,
    findings,
    coverage: {
      profile: "STANDARD",
      urls: 100,
      endpoints: 40,
      requests: 200,
      completedModules: ["CRAWLING", "PASSIVE_ANALYSIS", "SAFE_ACTIVE_ANALYSIS"],
      failedOrDegradedModules: [],
    },
    inventory: {
      assets: ["ORIGIN|https://fixture.test"],
      technologies: ["nginx|1.26"],
    },
    ...overrides,
  };
}

describe("monthly assessment comparison", () => {
  it("classifies a first assessment as new without claiming comparable coverage", () => {
    const result = compareAssessments(snapshot("current", [finding("one")]), null);
    expect(result).toMatchObject({
      previousScanId: null,
      coverageSufficient: false,
      counts: { NEW: 1, RESOLVED: 0, UNVERIFIED: 0 },
    });
    expect(result.findings[0]).toMatchObject({
      trendStatus: "NEW",
      remediationPriority: "FIX_NEXT",
    });
  });

  it("detects recurring, regressed, changed, new, and resolved findings", () => {
    const previous = snapshot("previous", [
      finding("recurring", { recurrenceCount: 2 }),
      finding("regressed", { severity: "LOW" }),
      finding("changed", { severity: "HIGH" }),
      finding("resolved"),
    ]);
    const current = snapshot(
      "current",
      [
        finding("recurring"),
        finding("regressed", { severity: "HIGH" }),
        finding("changed", { severity: "MEDIUM" }),
        finding("new"),
      ],
      {
        inventory: {
          assets: ["ORIGIN|https://fixture.test", "HOST|api.fixture.test"],
          technologies: ["nginx|1.26", "react|19"],
        },
      },
    );
    const result = compareAssessments(current, previous);
    expect(result.coverageSufficient).toBe(true);
    expect(result.counts).toMatchObject({
      NEW: 1,
      RECURRING: 1,
      REGRESSED: 1,
      CHANGED: 1,
      RESOLVED: 1,
      UNVERIFIED: 0,
    });
    expect(
      result.findings.find(({ correlationKey }) => correlationKey === "recurring"),
    ).toMatchObject({ recurrenceCount: 3, trendStatus: "RECURRING" });
    expect(result.newAssets).toEqual(["HOST|api.fixture.test"]);
    expect(result.technologyChanges.added).toEqual(["react|19"]);
  });

  it("marks a missing prior finding unverified when current coverage is insufficient", () => {
    const previous = snapshot("previous", [finding("missing")]);
    const current = snapshot("current", [], {
      coverage: {
        profile: "LIGHT",
        urls: 20,
        endpoints: 5,
        requests: 25,
        completedModules: ["CRAWLING"],
        failedOrDegradedModules: ["SAFE_ACTIVE_ANALYSIS"],
      },
    });
    const result = compareAssessments(current, previous);
    expect(result.coverageSufficient).toBe(false);
    expect(result.counts.UNVERIFIED).toBe(1);
    expect(result.counts.RESOLVED).toBe(0);
    expect(result.coverageReasons).not.toHaveLength(0);
  });

  it("prioritizes regression and recurrence without inventing asset criticality", () => {
    expect(
      prioritizeFinding({
        severity: "HIGH",
        confidence: 0.9,
        trendStatus: "REGRESSED",
        recurrenceCount: 3,
      }),
    ).toMatchObject({ priority: "FIX_NOW" });
    expect(
      prioritizeFinding({
        severity: "INFO",
        confidence: 0.95,
        trendStatus: "NEW",
        recurrenceCount: 1,
      }),
    ).toMatchObject({ priority: "HARDENING" });
    const oneEndpoint = prioritizeFinding({
      severity: "MEDIUM",
      confidence: 0.8,
      trendStatus: "RECURRING",
      recurrenceCount: 2,
      affectedEndpointCount: 1,
    });
    const broadFinding = prioritizeFinding({
      severity: "MEDIUM",
      confidence: 0.8,
      trendStatus: "RECURRING",
      recurrenceCount: 2,
      affectedEndpointCount: 16,
    });
    expect(broadFinding.score).toBeGreaterThan(oneEndpoint.score);
  });
});
