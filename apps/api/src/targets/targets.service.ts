import { createHash, randomBytes } from "node:crypto";
import { resolveTxt } from "node:dns/promises";
import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from "@nestjs/common";
import { TargetStatus, VerificationMethod, VerificationStatus } from "@aasp/database";
import { ScopeEngine, ScopedHttpClient, normalizeAssessmentUrl } from "@aasp/scope-engine";
import { AuditService } from "../audit/audit.service.js";
import type { AuthenticatedUser } from "../auth/auth.types.js";
import { PrismaService } from "../database/prisma.service.js";

const verificationLifetimeMs = 24 * 60 * 60 * 1000;
const authorizationLifetimeMs = 30 * 24 * 60 * 60 * 1000;

function tokenHash(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

function isFixtureHostname(hostname: string): boolean {
  return (
    hostname === "localhost" ||
    hostname === "127.0.0.1" ||
    hostname === "::1" ||
    hostname.endsWith(".internal")
  );
}

@Injectable()
export class TargetsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
  ) {}

  list(workspaceId: string) {
    return this.prisma.target.findMany({
      where: { workspaceId },
      include: { verifications: { orderBy: { createdAt: "desc" }, take: 1 } },
      orderBy: { createdAt: "desc" },
    });
  }

  async create(
    workspaceId: string,
    actorId: string,
    input: { name: string; url: string; method: VerificationMethod },
  ) {
    const parsed = normalizeAssessmentUrl(input.url);
    const origin = parsed.origin;
    const normalizedHostname = parsed.hostname.replace(/^\[|\]$/g, "");
    const token = randomBytes(32).toString("base64url");
    const target = await this.prisma.target.create({
      data: {
        workspaceId,
        createdById: actorId,
        name: input.name.trim(),
        origin,
        normalizedHostname,
        normalizedPort: parsed.port ? Number(parsed.port) : null,
        status: TargetStatus.PENDING_VERIFICATION,
        verifications: {
          create: {
            workspaceId,
            method: input.method,
            tokenHash: tokenHash(token),
            tokenHint: token.slice(0, 6),
            expiresAt: new Date(Date.now() + verificationLifetimeMs),
          },
        },
        scopeRules: {
          create: { workspaceId, type: "HOST", value: normalizedHostname },
        },
      },
      include: { verifications: { orderBy: { createdAt: "desc" }, take: 1 } },
    });
    await this.audit.record({
      workspaceId,
      actorId,
      action: "target.registered",
      resourceType: "Target",
      resourceId: target.id,
      metadata: { origin, verificationMethod: input.method },
    });
    return {
      target,
      verification: {
        method: input.method,
        token,
        dnsRecord: `_security-assessment.${normalizedHostname}`,
        dnsValue: `aasp-verification=${token}`,
        wellKnownUrl: `${origin}/.well-known/security-assessment-verification`,
      },
    };
  }

  async verify(
    workspaceId: string,
    targetId: string,
    actor: AuthenticatedUser,
    suppliedToken: string | undefined,
  ) {
    const target = await this.prisma.target.findFirst({
      where: { id: targetId, workspaceId },
      include: {
        verifications: {
          where: { status: VerificationStatus.PENDING },
          orderBy: { createdAt: "desc" },
          take: 1,
        },
      },
    });
    if (!target) throw new NotFoundException("Target does not exist in this workspace.");
    if (target.status === TargetStatus.DISABLED)
      throw new BadRequestException("Disabled targets cannot be verified.");
    const verification = target.verifications[0];
    if (!verification) throw new BadRequestException("No pending verification challenge exists.");
    if (verification.expiresAt <= new Date()) {
      await this.prisma.targetVerification.update({
        where: { id: verification.id },
        data: {
          status: VerificationStatus.EXPIRED,
          failureReason: "Verification challenge expired.",
        },
      });
      throw new BadRequestException("Verification challenge expired.");
    }

    try {
      if (verification.method === VerificationMethod.MANUAL_ADMIN) {
        if (!actor.isSystemAdmin)
          throw new ForbiddenException("Manual fixture approval requires a system administrator.");
        if (!isFixtureHostname(target.normalizedHostname)) {
          throw new ForbiddenException(
            "Manual approval is restricted to local or internal fixture hostnames.",
          );
        }
      } else {
        if (!suppliedToken || tokenHash(suppliedToken) !== verification.tokenHash) {
          throw new BadRequestException("Verification token is invalid.");
        }
        const policy = {
          targetOrigin: target.origin,
          includeSubdomains: false,
          allowPrivateNetwork: false,
        };
        const scopeEngine = new ScopeEngine();
        if (verification.method === VerificationMethod.DNS_TXT) {
          await scopeEngine.assertAllowed(target.origin, policy);
          const records = (
            await resolveTxt(`_security-assessment.${target.normalizedHostname}`)
          ).flat();
          if (!records.includes(`aasp-verification=${suppliedToken}`)) {
            throw new BadRequestException("Expected DNS TXT verification value was not found.");
          }
        } else {
          const client = new ScopedHttpClient(scopeEngine, policy);
          const response = await client.request(
            `${target.origin}/.well-known/security-assessment-verification`,
            { timeoutMs: 8_000, maxResponseBytes: 4_096, followRedirects: false },
          );
          if (
            response.statusCode !== 200 ||
            response.body.toString("utf8").trim() !== suppliedToken
          ) {
            throw new BadRequestException(
              "Well-known verification response did not match the challenge.",
            );
          }
        }
      }
    } catch (error: unknown) {
      await this.prisma.targetVerification.update({
        where: { id: verification.id },
        data: {
          attemptCount: { increment: 1 },
          lastAttemptAt: new Date(),
          failureReason:
            error instanceof Error ? error.message.slice(0, 500) : "Verification failed.",
        },
      });
      throw error;
    }

    const now = new Date();
    const verifiedTarget = await this.prisma.$transaction(async (transaction) => {
      await transaction.targetVerification.update({
        where: { id: verification.id },
        data: {
          status: VerificationStatus.SUCCEEDED,
          attemptCount: { increment: 1 },
          lastAttemptAt: now,
          verifiedAt: now,
          verifierUserId: actor.id,
          failureReason: null,
        },
      });
      return transaction.target.update({
        where: { id: target.id },
        data: {
          status: TargetStatus.VERIFIED,
          verifiedAt: now,
          authorizationExpiresAt: new Date(now.getTime() + authorizationLifetimeMs),
          allowPrivateNetwork: verification.method === VerificationMethod.MANUAL_ADMIN,
        },
      });
    });
    await this.audit.record({
      workspaceId,
      actorId: actor.id,
      action: "target.verified",
      resourceType: "Target",
      resourceId: target.id,
      metadata: {
        method: verification.method,
        allowPrivateNetwork: verifiedTarget.allowPrivateNetwork,
      },
    });
    return verifiedTarget;
  }
}
