import { ForbiddenException, Injectable, NotFoundException } from "@nestjs/common";
import { ModelProviderStatus } from "@aasp/database";
import {
  decryptProviderSecret,
  encryptProviderSecret,
  normalizeProviderBaseUrl,
  QwenClient,
} from "@aasp/ai-engine";
import { AuditService } from "../audit/audit.service.js";
import type { AuthenticatedUser } from "../auth/auth.types.js";
import { PrismaService } from "../database/prisma.service.js";

interface ConfigureProviderInput {
  name: string;
  baseUrl: string;
  modelName: string;
  apiKey?: string;
}

function allowedHosts(): string[] {
  return (process.env["QWEN_PROVIDER_ALLOWED_HOSTS"] ?? "")
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function assertSystemAdmin(actor: AuthenticatedUser): void {
  if (!actor.isSystemAdmin) {
    throw new ForbiddenException("Model provider configuration requires a system administrator.");
  }
}

function publicProvider(provider: {
  id: string;
  name: string;
  baseUrl: string;
  modelName: string;
  encryptedApiKey: string | null;
  status: ModelProviderStatus;
  lastHeartbeat: Date | null;
  lastError: string | null;
  createdAt: Date;
  updatedAt: Date;
}) {
  return {
    id: provider.id,
    name: provider.name,
    baseUrl: provider.baseUrl,
    modelName: provider.modelName,
    apiKeyConfigured: Boolean(provider.encryptedApiKey),
    status: provider.status,
    lastHeartbeat: provider.lastHeartbeat,
    lastError: provider.lastError,
    createdAt: provider.createdAt,
    updatedAt: provider.updatedAt,
  };
}

@Injectable()
export class ModelProvidersService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
  ) {}

  async list(workspaceId: string) {
    const providers = await this.prisma.modelProvider.findMany({
      where: { workspaceId },
      orderBy: { updatedAt: "desc" },
    });
    return providers.map(publicProvider);
  }

  async configure(workspaceId: string, actor: AuthenticatedUser, input: ConfigureProviderInput) {
    assertSystemAdmin(actor);
    const providerHosts = allowedHosts();
    if (providerHosts.length === 0) {
      throw new ForbiddenException("QWEN_PROVIDER_ALLOWED_HOSTS must be configured first.");
    }
    const baseUrl = normalizeProviderBaseUrl(input.baseUrl, providerHosts);
    let encryptedSecret:
      | { encryptedApiKey: string; apiKeyInitializationVector: string }
      | undefined;
    if (input.apiKey) {
      const encryptionKey = process.env["MODEL_PROVIDER_ENCRYPTION_KEY"];
      if (!encryptionKey) {
        throw new ForbiddenException("MODEL_PROVIDER_ENCRYPTION_KEY is not configured.");
      }
      const encrypted = encryptProviderSecret(input.apiKey, encryptionKey);
      encryptedSecret = {
        encryptedApiKey: encrypted.encryptedValue,
        apiKeyInitializationVector: encrypted.initializationVector,
      };
    }
    const provider = await this.prisma.modelProvider.upsert({
      where: { workspaceId_name: { workspaceId, name: input.name.trim() } },
      create: {
        workspaceId,
        name: input.name.trim(),
        baseUrl,
        modelName: input.modelName,
        status: ModelProviderStatus.UNKNOWN,
        ...encryptedSecret,
      },
      update: {
        baseUrl,
        modelName: input.modelName,
        status: ModelProviderStatus.UNKNOWN,
        lastError: null,
        ...encryptedSecret,
      },
    });
    await this.audit.record({
      workspaceId,
      actorId: actor.id,
      action: "model_provider.configured",
      resourceType: "ModelProvider",
      resourceId: provider.id,
      metadata: { name: provider.name, baseUrl, modelName: provider.modelName },
    });
    return publicProvider(provider);
  }

  async health(workspaceId: string, providerId: string, actor: AuthenticatedUser) {
    assertSystemAdmin(actor);
    const provider = await this.prisma.modelProvider.findFirst({
      where: { id: providerId, workspaceId },
    });
    if (!provider) throw new NotFoundException("Model provider does not exist in this workspace.");
    let apiKey: string | undefined;
    if (provider.encryptedApiKey && provider.apiKeyInitializationVector) {
      const encryptionKey = process.env["MODEL_PROVIDER_ENCRYPTION_KEY"];
      if (!encryptionKey) {
        throw new ForbiddenException("MODEL_PROVIDER_ENCRYPTION_KEY is not configured.");
      }
      apiKey = decryptProviderSecret(
        provider.encryptedApiKey,
        provider.apiKeyInitializationVector,
        encryptionKey,
      );
    }
    const result = await new QwenClient({
      baseUrl: provider.baseUrl,
      modelName: provider.modelName,
      ...(apiKey ? { apiKey } : {}),
    }).health();
    const status = result.online ? ModelProviderStatus.ONLINE : ModelProviderStatus.OFFLINE;
    const updated = await this.prisma.modelProvider.update({
      where: { id: provider.id },
      data: {
        status,
        lastHeartbeat: new Date(),
        lastError: result.online ? null : result.detail.slice(0, 1_000),
      },
    });
    await this.audit.record({
      workspaceId,
      actorId: actor.id,
      action: "model_provider.health_checked",
      resourceType: "ModelProvider",
      resourceId: provider.id,
      metadata: { status, latencyMs: result.latencyMs },
    });
    return { ...publicProvider(updated), health: result };
  }
}
