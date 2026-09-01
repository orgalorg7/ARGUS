import type { TargetStatus } from "@aasp/schemas";

export class TargetAuthorizationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TargetAuthorizationError";
  }
}

export interface TargetAuthorizationSnapshot {
  status: TargetStatus;
  authorizationExpiresAt: Date | null;
  disabledAt?: Date | null;
}

export function assertCurrentTargetAuthorization(
  target: TargetAuthorizationSnapshot,
  now: Date = new Date(),
): void {
  if (target.status !== "VERIFIED") {
    throw new TargetAuthorizationError(
      `Target status ${target.status} does not permit an assessment.`,
    );
  }
  if (target.disabledAt) throw new TargetAuthorizationError("Target has been disabled.");
  if (!target.authorizationExpiresAt || target.authorizationExpiresAt <= now) {
    throw new TargetAuthorizationError("Target authorization is missing or expired.");
  }
}
