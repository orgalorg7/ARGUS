import { createHash } from "node:crypto";
import type { AuthenticationState } from "./types.js";

export interface SessionFingerprintSource {
  sessionFingerprint(): string | null;
}

export interface SessionRotationResult {
  beforeFingerprint: string | null;
  afterFingerprint: string | null;
  rotated: boolean | null;
  state: AuthenticationState;
  observedAt: string;
}

export interface LogoutInvalidationResult {
  beforeStatus: number;
  logoutStatus: number;
  afterStatus: number;
  previousSessionStillUsable: boolean;
  sessionFingerprint: string | null;
  observedAt: string;
}

export async function testSessionRotation(input: {
  context: SessionFingerprintSource;
  securityRelevantTransition: () => Promise<void>;
}): Promise<SessionRotationResult> {
  const beforeFingerprint = input.context.sessionFingerprint();
  await input.securityRelevantTransition();
  const afterFingerprint = input.context.sessionFingerprint();
  return {
    beforeFingerprint,
    afterFingerprint,
    rotated:
      beforeFingerprint === null || afterFingerprint === null
        ? null
        : beforeFingerprint !== afterFingerprint,
    state: afterFingerprint ? "AUTHENTICATED" : "UNKNOWN",
    observedAt: new Date().toISOString(),
  };
}

export async function testLogoutInvalidation(input: {
  context: SessionFingerprintSource;
  authorizedRequest: () => Promise<number>;
  logout: () => Promise<number>;
  replayPreviousSessionRequest: () => Promise<number>;
}): Promise<LogoutInvalidationResult> {
  const fingerprint = input.context.sessionFingerprint();
  const beforeStatus = await input.authorizedRequest();
  const logoutStatus = await input.logout();
  const afterStatus = await input.replayPreviousSessionRequest();
  return {
    beforeStatus,
    logoutStatus,
    afterStatus,
    previousSessionStillUsable: beforeStatus < 400 && afterStatus < 400,
    sessionFingerprint: fingerprint ? createHash("sha256").update(fingerprint).digest("hex") : null,
    observedAt: new Date().toISOString(),
  };
}
