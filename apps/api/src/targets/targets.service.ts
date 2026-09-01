import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
} from "@nestjs/common";
import { TargetStatus, type Prisma } from "@aasp/database";
import { targetScopeSchema, type TargetScopeInput } from "@aasp/schemas";
import { normalizeAssessmentUrl, scopePolicyFromTarget } from "@aasp/scope-engine";
import { AuditService } from "../audit/audit.service.js";
import { PrismaService } from "../database/prisma.service.js";

interface NormalizedTargetScope {
  allowedDomains: string[];
  includeSubdomains: boolean;
  allowedPorts: number[];
  excludedPaths: string[];
  allowPrivateNetwork: boolean;
}

function normalizeDomain(input: string): string {
  const trimmed = input.trim().toLowerCase().replace(/\.$/u, "");
  let parsed: URL;
  try {
    parsed = normalizeAssessmentUrl(`http://${trimmed}`);
  } catch {
    throw new BadRequestException(`Allowed domain is invalid: ${input}`);
  }
  if (
    parsed.port ||
    parsed.pathname !== "/" ||
    parsed.search ||
    parsed.hash ||
    parsed.username ||
    parsed.password
  ) {
    throw new BadRequestException(`Allowed domain must contain only a hostname: ${input}`);
  }
  return parsed.hostname.replace(/^\[|\]$/gu, "");
}

function normalizeExcludedPath(input: string): string {
  const trimmed = input.trim();
  if (!trimmed.startsWith("/") || trimmed.includes("?") || trimmed.includes("#")) {
    throw new BadRequestException(
      `Excluded path must be an absolute path without a query: ${input}`,
    );
  }
  const normalized = new URL(trimmed, "https://scope.invalid").pathname;
  if (normalized !== trimmed || normalized.includes("//")) {
    throw new BadRequestException(`Excluded path is not canonical: ${input}`);
  }
  return normalized;
}

function normalizeScope(origin: URL, input: TargetScopeInput): NormalizedTargetScope {
  const parsed = targetScopeSchema.safeParse(input);
  if (!parsed.success) {
    throw new BadRequestException(parsed.error.issues.map(({ message }) => message).join(" "));
  }
  const allowedDomains = [...new Set(parsed.data.allowedDomains.map(normalizeDomain))].sort();
  const originHostname = origin.hostname.replace(/^\[|\]$/gu, "");
  if (!allowedDomains.includes(originHostname)) {
    throw new BadRequestException(
      "The target origin hostname must be explicitly included in allowedDomains.",
    );
  }
  const allowedPorts = [...new Set(parsed.data.allowedPorts)].sort((left, right) => left - right);
  const originPort = Number(origin.port || (origin.protocol === "https:" ? 443 : 80));
  if (!allowedPorts.includes(originPort)) {
    throw new BadRequestException(
      `The target origin port ${originPort} must be explicitly included in allowedPorts.`,
    );
  }
  return {
    allowedDomains,
    includeSubdomains: parsed.data.includeSubdomains,
    allowedPorts,
    excludedPaths: [...new Set(parsed.data.excludedPaths.map(normalizeExcludedPath))].sort(),
    allowPrivateNetwork: parsed.data.allowPrivateNetwork,
  };
}

function scopeRuleData(
  workspaceId: string,
  scope: NormalizedTargetScope,
): Prisma.ScopeRuleUncheckedCreateWithoutTargetInput[] {
  return [
    ...scope.allowedDomains.map((value) => ({ workspaceId, type: "HOST" as const, value })),
    ...scope.allowedPorts.map((value) => ({
      workspaceId,
      type: "PORT" as const,
      value: String(value),
    })),
    ...scope.excludedPaths.map((value) => ({
      workspaceId,
      type: "PATH_EXCLUDE" as const,
      value,
    })),
  ];
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
      include: {
        scopeRules: {
          where: { enabled: true },
          orderBy: [{ type: "asc" }, { value: "asc" }],
        },
      },
      orderBy: { createdAt: "desc" },
    });
  }

  async create(
    workspaceId: string,
    actorId: string,
    input: { name: string; url: string; scope?: TargetScopeInput },
  ) {
    const origin = normalizeAssessmentUrl(input.url);
    const normalizedHostname = origin.hostname.replace(/^\[|\]$/gu, "");
    const scope = input.scope ? normalizeScope(origin, input.scope) : null;
    const target = await this.prisma.target.create({
      data: {
        workspaceId,
        createdById: actorId,
        name: input.name.trim(),
        origin: origin.origin,
        normalizedHostname,
        normalizedPort: origin.port ? Number(origin.port) : null,
        status: scope ? TargetStatus.READY : TargetStatus.DRAFT,
        includeSubdomains: scope?.includeSubdomains ?? false,
        allowPrivateNetwork: scope?.allowPrivateNetwork ?? false,
        ...(scope ? { scopeRules: { create: scopeRuleData(workspaceId, scope) } } : {}),
      },
      include: {
        scopeRules: {
          where: { enabled: true },
          orderBy: [{ type: "asc" }, { value: "asc" }],
        },
      },
    });
    await this.audit.record({
      workspaceId,
      actorId,
      action: scope ? "target.scope_configured" : "target.created",
      resourceType: "Target",
      resourceId: target.id,
      metadata: {
        origin: target.origin,
        status: target.status,
        allowedDomains: scope?.allowedDomains ?? [],
        allowedPorts: scope?.allowedPorts ?? [],
      },
    });
    return target;
  }

  async configureScope(
    workspaceId: string,
    targetId: string,
    actorId: string,
    input: TargetScopeInput,
  ) {
    const target = await this.prisma.target.findFirst({ where: { id: targetId, workspaceId } });
    if (!target) throw new NotFoundException("Target does not exist in this workspace.");
    if (target.status === TargetStatus.SCANNING) {
      throw new ConflictException("Target scope cannot change while an assessment is running.");
    }
    if (target.status === TargetStatus.DISABLED) {
      throw new ConflictException("A disabled target cannot be reconfigured.");
    }
    const scope = normalizeScope(normalizeAssessmentUrl(target.origin), input);
    const updated = await this.prisma.$transaction(async (transaction) => {
      await transaction.scopeRule.deleteMany({ where: { workspaceId, targetId } });
      return transaction.target.update({
        where: { id: targetId },
        data: {
          status: TargetStatus.READY,
          includeSubdomains: scope.includeSubdomains,
          allowPrivateNetwork: scope.allowPrivateNetwork,
          scopeRules: { create: scopeRuleData(workspaceId, scope) },
        },
        include: {
          scopeRules: {
            where: { enabled: true },
            orderBy: [{ type: "asc" }, { value: "asc" }],
          },
        },
      });
    });
    scopePolicyFromTarget(updated);
    await this.audit.record({
      workspaceId,
      actorId,
      action: "target.scope_configured",
      resourceType: "Target",
      resourceId: targetId,
      metadata: {
        allowedDomains: scope.allowedDomains,
        includeSubdomains: scope.includeSubdomains,
        allowedPorts: scope.allowedPorts,
        excludedPaths: scope.excludedPaths,
        allowPrivateNetwork: scope.allowPrivateNetwork,
      },
    });
    return updated;
  }

  async disable(workspaceId: string, targetId: string, actorId: string) {
    const target = await this.prisma.target.findFirst({ where: { id: targetId, workspaceId } });
    if (!target) throw new NotFoundException("Target does not exist in this workspace.");
    if (target.status === TargetStatus.SCANNING) {
      throw new ConflictException("Cancel the running assessment before disabling its target.");
    }
    const updated = await this.prisma.target.update({
      where: { id: targetId },
      data: { status: TargetStatus.DISABLED, disabledAt: new Date() },
    });
    await this.audit.record({
      workspaceId,
      actorId,
      action: "target.disabled",
      resourceType: "Target",
      resourceId: targetId,
    });
    return updated;
  }
}
