import { createHash } from "node:crypto";
import type { Prisma, PrismaClient } from "@aasp/database";
import { scannerObservationInputSchema, type ScannerObservationInput } from "@aasp/schemas";
import { redactText, redactUnknown } from "@aasp/security-core";

export interface PersistedObservation {
  observationId: string;
  evidenceIds: string[];
  signature: string;
}

function stableValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, nested]) => [key, stableValue(nested)]),
    );
  }
  return value;
}

function stableJson(value: unknown): string {
  return JSON.stringify(stableValue(value));
}

function sha256(value: unknown): string {
  return createHash("sha256").update(stableJson(value)).digest("hex");
}

function jsonValue(value: unknown): Prisma.InputJsonValue {
  return JSON.parse(JSON.stringify(value)) as Prisma.InputJsonValue;
}

export class EvidenceEngine {
  constructor(private readonly prisma: PrismaClient) {}

  async record(
    workspaceId: string,
    scanId: string,
    candidate: ScannerObservationInput,
  ): Promise<PersistedObservation> {
    const input = scannerObservationInputSchema.parse(candidate);
    const redactedMetadata = redactUnknown(input.metadata);
    const signature = sha256({
      scanner: input.scanner,
      observationType: input.observationType,
      asset: input.asset,
      endpoint: input.endpoint ?? null,
      method: input.method ?? null,
      parameter: input.parameter ?? null,
      metadata: redactedMetadata,
    });

    const existing = await this.prisma.scannerObservation.findFirst({
      where: { workspaceId, scanId, signature },
      include: { evidence: { select: { id: true } } },
    });
    if (existing) {
      return {
        observationId: existing.id,
        evidenceIds: existing.evidence.map((item) => item.id),
        signature,
      };
    }

    return this.prisma.$transaction(async (transaction) => {
      const observation = await transaction.scannerObservation.create({
        data: {
          workspaceId,
          scanId,
          scanner: input.scanner,
          scannerVersion: input.scannerVersion,
          observationType: input.observationType,
          asset: input.asset,
          ...(input.endpoint ? { endpoint: input.endpoint } : {}),
          ...(input.method ? { method: input.method } : {}),
          ...(input.parameter ? { parameter: input.parameter } : {}),
          ...(input.rawSeverity ? { rawSeverity: input.rawSeverity } : {}),
          metadata: jsonValue(redactedMetadata),
          signature,
        },
      });
      const evidenceIds: string[] = [];
      for (const item of input.evidence) {
        const requestMetadata = redactUnknown(item.requestMetadata);
        const responseMetadata = redactUnknown(item.responseMetadata);
        const redactedExcerpt = redactText(item.excerpt).slice(0, 65_536);
        const hash = sha256({
          source: item.source,
          asset: item.asset,
          requestMetadata,
          responseMetadata,
          redactedExcerpt,
        });
        const evidence = await transaction.evidence.create({
          data: {
            workspaceId,
            scanId,
            observationId: observation.id,
            source: item.source,
            asset: item.asset,
            requestMetadata: jsonValue(requestMetadata),
            responseMetadata: jsonValue(responseMetadata),
            redactedExcerpt,
            hash,
          },
        });
        evidenceIds.push(evidence.id);
      }
      return { observationId: observation.id, evidenceIds, signature };
    });
  }
}
