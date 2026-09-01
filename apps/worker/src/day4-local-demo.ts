import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { correlateFindings } from "@aasp/correlation-engine";
import { normalizeObservations, type FindingObservationRecord } from "@aasp/finding-engine";
import {
  scannerObservationInputSchema,
  type ScannerEvidenceInput,
  type ScannerObservationInput,
} from "@aasp/schemas";

interface Day3Artifact {
  generatedAt: string;
  target: string;
  observations: unknown[];
}

function sha256(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function evidenceRecord(
  item: ScannerEvidenceInput,
  observationIndex: number,
  evidenceIndex: number,
  timestamp: Date,
) {
  const hash = sha256(item);
  return {
    id: `EVID-LOCAL-${String(observationIndex + 1).padStart(4, "0")}-${String(evidenceIndex + 1).padStart(2, "0")}`,
    timestamp,
    source: item.source,
    asset: item.asset,
    hash,
    requestMetadata: item.requestMetadata,
    responseMetadata: item.responseMetadata,
    redactedExcerpt: item.excerpt,
  };
}

function observationRecord(
  item: ScannerObservationInput,
  index: number,
  timestamp: Date,
): FindingObservationRecord {
  return {
    id: `OBS-LOCAL-${String(index + 1).padStart(4, "0")}`,
    scanner: item.scanner,
    scannerVersion: item.scannerVersion,
    observationType: item.observationType,
    asset: item.asset,
    endpoint: item.endpoint ?? null,
    method: item.method ?? null,
    parameter: item.parameter ?? null,
    rawSeverity: item.rawSeverity ?? null,
    metadata: item.metadata,
    createdAt: timestamp,
    evidence: item.evidence.map((evidence, evidenceIndex) =>
      evidenceRecord(evidence, index, evidenceIndex, timestamp),
    ),
  };
}

const inputPath = resolve(
  process.env["DAY4_OBSERVATIONS_PATH"] ?? "../../artifacts/day3-scanner-observations.json",
);
const outputPath = resolve(
  process.env["DAY4_FINDINGS_PATH"] ?? "../../artifacts/day4-correlated-findings.json",
);
const decoded = JSON.parse(await readFile(inputPath, "utf8")) as Partial<Day3Artifact>;
if (!decoded.generatedAt || !decoded.target || !Array.isArray(decoded.observations)) {
  throw new Error("Day 3 artifact is missing generatedAt, target, or observations.");
}
const timestamp = new Date(decoded.generatedAt);
if (Number.isNaN(timestamp.getTime())) throw new Error("Day 3 generatedAt timestamp is invalid.");
const observations = decoded.observations.map((item) => scannerObservationInputSchema.parse(item));
const candidates = normalizeObservations(
  observations.map((item, index) => observationRecord(item, index, timestamp)),
);
const findings = correlateFindings(candidates).map((finding, index) => ({
  id: `FIND-${String(index + 1).padStart(4, "0")}`,
  ...finding,
  firstSeen: finding.firstSeen.toISOString(),
  lastSeen: finding.lastSeen.toISOString(),
}));
const artifact = {
  generatedAt: new Date().toISOString(),
  sourceArtifact: inputPath,
  target: decoded.target,
  sourceObservationCount: observations.length,
  normalizedCandidateCount: candidates.length,
  correlatedFindingCount: findings.length,
  aiAnalysisPerformed: false,
  findings,
};
await mkdir(dirname(outputPath), { recursive: true });
await writeFile(outputPath, `${JSON.stringify(artifact, null, 2)}\n`, { mode: 0o600 });
process.stdout.write(
  `${JSON.stringify({ outputPath, sourceObservations: observations.length, candidates: candidates.length, findings: findings.length, aiAnalysisPerformed: false })}\n`,
);
