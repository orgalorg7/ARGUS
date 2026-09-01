import type { TargetStatus } from "@aasp/schemas";

export class TargetReadinessError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TargetReadinessError";
  }
}

export interface TargetReadiness {
  status: TargetStatus;
}

const startableStatuses = new Set<TargetStatus>(["READY", "COMPLETED", "FAILED", "CANCELLED"]);

export function assertTargetReadyForScan(target: TargetReadiness): void {
  if (!startableStatuses.has(target.status)) {
    throw new TargetReadinessError(
      target.status === "DRAFT"
        ? "Target scope configuration is incomplete."
        : `Target status ${target.status} does not permit a new scan.`,
    );
  }
}
