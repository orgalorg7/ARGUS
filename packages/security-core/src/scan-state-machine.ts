import type { ScanState } from "@aasp/schemas";

const transitions: Readonly<Record<ScanState, readonly ScanState[]>> = {
  CREATED: ["WAITING_FOR_TARGET_VERIFICATION", "AUTHORIZED", "CANCELLED"],
  WAITING_FOR_TARGET_VERIFICATION: ["AUTHORIZED", "CANCELLED", "FAILED"],
  AUTHORIZED: ["QUEUED", "CANCELLED"],
  QUEUED: ["VALIDATING_SCOPE", "CANCELLED", "FAILED"],
  VALIDATING_SCOPE: ["DISCOVERY", "CANCELLED", "FAILED"],
  DISCOVERY: ["CRAWLING", "CANCELLED", "FAILED"],
  CRAWLING: ["API_DISCOVERY", "CANCELLED", "FAILED"],
  API_DISCOVERY: ["FINGERPRINTING", "CANCELLED", "FAILED"],
  FINGERPRINTING: ["PASSIVE_ANALYSIS", "CANCELLED", "FAILED"],
  PASSIVE_ANALYSIS: ["SAFE_ACTIVE_ANALYSIS", "CANCELLED", "FAILED"],
  SAFE_ACTIVE_ANALYSIS: ["NORMALIZING", "CANCELLED", "FAILED"],
  NORMALIZING: ["CORRELATING", "CANCELLED", "FAILED"],
  CORRELATING: ["AI_ANALYSIS", "AI_ANALYSIS_WAITING_FOR_PROVIDER", "CANCELLED", "FAILED"],
  AI_ANALYSIS: [
    "AI_ANALYSIS_WAITING_FOR_PROVIDER",
    "GENERATING_SCAN_REPORT",
    "CANCELLED",
    "FAILED",
  ],
  AI_ANALYSIS_WAITING_FOR_PROVIDER: [
    "AI_ANALYSIS",
    "GENERATING_SCAN_REPORT",
    "CANCELLED",
    "FAILED",
  ],
  GENERATING_SCAN_REPORT: ["GENERATING_VULNERABILITY_REPORTS", "CANCELLED", "FAILED"],
  GENERATING_VULNERABILITY_REPORTS: ["COMPLETED", "COMPLETED_WITH_WARNINGS", "CANCELLED", "FAILED"],
  COMPLETED: [],
  COMPLETED_WITH_WARNINGS: [],
  FAILED: [],
  CANCELLED: [],
};

export class InvalidScanTransitionError extends Error {
  constructor(
    readonly from: ScanState,
    readonly to: ScanState,
  ) {
    super(`Scan transition from ${from} to ${to} is not allowed.`);
    this.name = "InvalidScanTransitionError";
  }
}

export function assertScanTransition(from: ScanState, to: ScanState): void {
  if (!transitions[from].includes(to)) throw new InvalidScanTransitionError(from, to);
}

export function allowedScanTransitions(from: ScanState): readonly ScanState[] {
  return transitions[from];
}
