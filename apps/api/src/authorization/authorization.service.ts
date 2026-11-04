import { BadRequestException, Injectable, NotFoundException } from "@nestjs/common";
import { IdentityAuthenticationState, IdentityAuthenticationType, Prisma } from "@aasp/database";
import { encryptCredential, type CredentialMaterial } from "@aasp/authorization-engine";
import { AuditService } from "../audit/audit.service.js";
import { PrismaService } from "../database/prisma.service.js";

const protectedHeader = /^(authorization|cookie|set-cookie|proxy-authorization|x-api-key)$/i;

function encryptionKey(): string {
  const key = process.env["IDENTITY_SECRET_ENCRYPTION_KEY"];
  if (!key) throw new BadRequestException("Identity secret storage is not configured.");
  return key;
}

function credentialMaterial(
  type: IdentityAuthenticationType,
  value: Record<string, unknown>,
): CredentialMaterial {
  if (type === IdentityAuthenticationType.ANONYMOUS) return { type: "ANONYMOUS" };
  if (type === IdentityAuthenticationType.USERNAME_PASSWORD) {
    if (typeof value["username"] !== "string" || typeof value["password"] !== "string") {
      throw new BadRequestException("Username/password identities require username and password.");
    }
    return { type: "USERNAME_PASSWORD", username: value["username"], password: value["password"] };
  }
  if (type === IdentityAuthenticationType.SESSION_COOKIE) {
    if (typeof value["name"] !== "string" || typeof value["value"] !== "string") {
      throw new BadRequestException("Session-cookie identities require name and value.");
    }
    return {
      type: "SESSION_COOKIE",
      name: value["name"],
      value: value["value"],
      ...(typeof value["domain"] === "string" ? { domain: value["domain"] } : {}),
      ...(typeof value["path"] === "string" ? { path: value["path"] } : {}),
    };
  }
  if (type === IdentityAuthenticationType.BEARER_TOKEN) {
    if (typeof value["token"] !== "string")
      throw new BadRequestException("Bearer identity requires token.");
    return { type: "BEARER_TOKEN", token: value["token"] };
  }
  if (type === IdentityAuthenticationType.API_KEY) {
    if (typeof value["headerName"] !== "string" || typeof value["value"] !== "string") {
      throw new BadRequestException("API-key identity requires headerName and value.");
    }
    return { type: "API_KEY", headerName: value["headerName"], value: value["value"] };
  }
  if (type === IdentityAuthenticationType.CUSTOM_HEADERS) {
    const headers = value["headers"];
    if (!headers || typeof headers !== "object" || Array.isArray(headers)) {
      throw new BadRequestException("Custom-header identity requires a headers object.");
    }
    if (Object.values(headers).some((entry) => typeof entry !== "string")) {
      throw new BadRequestException("Custom identity header values must be strings.");
    }
    return { type: "CUSTOM_HEADERS", headers: headers as Record<string, string> };
  }
  const adapterConfig = value["adapterConfig"];
  if (!adapterConfig || typeof adapterConfig !== "object" || Array.isArray(adapterConfig)) {
    throw new BadRequestException(`${type} requires adapterConfig.`);
  }
  return type === IdentityAuthenticationType.OAUTH_OIDC
    ? { type: "OAUTH_OIDC", adapterConfig: adapterConfig as Record<string, unknown> }
    : { type: "LOGIN_AUTOMATION", adapterConfig: adapterConfig as Record<string, unknown> };
}

function publicIdentity<
  T extends {
    encryptedCredential: unknown;
    lastFailureReason: string | null;
    authenticationState: IdentityAuthenticationState;
  },
>(identity: T) {
  const { encryptedCredential, lastFailureReason, ...safe } = identity;
  return {
    ...safe,
    credentialConfigured: encryptedCredential !== null,
    authenticationHealthy:
      identity.authenticationState === IdentityAuthenticationState.AUTHENTICATED,
    lastFailure: lastFailureReason ? "Authentication failed; inspect worker health events." : null,
  };
}

@Injectable()
export class AuthorizationService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
  ) {}

  async listIdentities(workspaceId: string, targetId: string) {
    await this.assertTarget(workspaceId, targetId);
    const identities = await this.prisma.assessmentIdentity.findMany({
      where: { workspaceId, targetId },
      orderBy: [{ enabled: "desc" }, { label: "asc" }],
    });
    return identities.map(publicIdentity);
  }

  async createIdentity(
    workspaceId: string,
    targetId: string,
    actorId: string,
    input: {
      label: string;
      role: string;
      tenant?: string;
      authenticationType: IdentityAuthenticationType;
      credential: Record<string, unknown>;
      metadata?: Record<string, unknown>;
    },
  ) {
    await this.assertTarget(workspaceId, targetId);
    const material = credentialMaterial(input.authenticationType, input.credential);
    const encrypted =
      material.type === "ANONYMOUS" ? null : encryptCredential(material, encryptionKey());
    const identity = await this.prisma.assessmentIdentity.create({
      data: {
        workspaceId,
        targetId,
        label: input.label.trim(),
        role: input.role.trim(),
        tenant: input.tenant?.trim() || null,
        authenticationType: input.authenticationType,
        authenticationState:
          material.type === "ANONYMOUS"
            ? IdentityAuthenticationState.UNKNOWN
            : IdentityAuthenticationState.UNKNOWN,
        encryptedCredential: encrypted as unknown as Prisma.InputJsonValue,
        credentialFingerprint: encrypted?.fingerprint ?? null,
        metadata: (input.metadata ?? {}) as Prisma.InputJsonValue,
      },
    });
    await this.audit.record({
      workspaceId,
      actorId,
      action: "identity.created",
      resourceType: "AssessmentIdentity",
      resourceId: identity.id,
      metadata: {
        targetId,
        label: identity.label,
        role: identity.role,
        tenant: identity.tenant,
        authenticationType: identity.authenticationType,
      },
    });
    return publicIdentity(identity);
  }

  async disableIdentity(
    workspaceId: string,
    targetId: string,
    identityId: string,
    actorId: string,
  ) {
    const identity = await this.prisma.assessmentIdentity.findFirst({
      where: { id: identityId, workspaceId, targetId },
    });
    if (!identity) throw new NotFoundException("Identity does not exist in this target.");
    const updated = await this.prisma.assessmentIdentity.update({
      where: { id: identityId },
      data: {
        enabled: false,
        authenticationState: IdentityAuthenticationState.UNAVAILABLE,
        encryptedCredential: Prisma.JsonNull,
        credentialFingerprint: null,
      },
    });
    await this.audit.record({
      workspaceId,
      actorId,
      action: "identity.disabled",
      resourceType: "AssessmentIdentity",
      resourceId: identityId,
      metadata: { targetId },
    });
    return publicIdentity(updated);
  }

  async listResources(workspaceId: string, targetId: string) {
    await this.assertTarget(workspaceId, targetId);
    return this.prisma.authorizedResource.findMany({
      where: { workspaceId, targetId },
      include: {
        ownerIdentity: { select: { id: true, label: true, role: true, tenant: true } },
        relationships: { include: { identity: { select: { id: true, label: true } } } },
      },
      orderBy: { createdAt: "desc" },
    });
  }

  async createResource(
    workspaceId: string,
    targetId: string,
    actorId: string,
    input: {
      resourceType: string;
      externalId: string;
      tenant?: string;
      ownerIdentityId?: string;
      provenance: "OPERATOR_SUPPLIED" | "SCANNER_CREATED" | "APPROVED_SEED" | "IDENTITY_OBSERVED";
      endpointVariables?: Record<string, string>;
      metadata?: Record<string, unknown>;
      relationships?: Array<{
        identityId: string;
        relationship:
          | "OWNS"
          | "MEMBER_OF"
          | "ADMIN_OF"
          | "MANAGER_OF"
          | "BELONGS_TO_TENANT"
          | "SHARED_WITH";
      }>;
    },
  ) {
    await this.assertTarget(workspaceId, targetId);
    const referencedIdentityIds = [
      ...(input.ownerIdentityId ? [input.ownerIdentityId] : []),
      ...(input.relationships ?? []).map(({ identityId }) => identityId),
    ];
    const identityCount = await this.prisma.assessmentIdentity.count({
      where: { id: { in: [...new Set(referencedIdentityIds)] }, workspaceId, targetId },
    });
    if (identityCount !== new Set(referencedIdentityIds).size) {
      throw new BadRequestException(
        "Every resource relationship must reference an identity on this target.",
      );
    }
    const relationships = [...(input.relationships ?? [])];
    if (
      input.ownerIdentityId &&
      !relationships.some(
        ({ identityId, relationship }) =>
          identityId === input.ownerIdentityId && relationship === "OWNS",
      )
    )
      relationships.push({ identityId: input.ownerIdentityId, relationship: "OWNS" });
    const resource = await this.prisma.authorizedResource.create({
      data: {
        workspaceId,
        targetId,
        resourceType: input.resourceType.trim(),
        externalId: input.externalId,
        tenant: input.tenant?.trim() || null,
        ownerIdentityId: input.ownerIdentityId ?? null,
        provenance: input.provenance,
        endpointVariables: (input.endpointVariables ?? {}) as Prisma.InputJsonValue,
        metadata: (input.metadata ?? {}) as Prisma.InputJsonValue,
        relationships: {
          create: relationships.map(({ identityId, relationship }) => ({
            identityId,
            relationship,
          })),
        },
      },
      include: { relationships: true },
    });
    await this.audit.record({
      workspaceId,
      actorId,
      action: "authorization_resource.created",
      resourceType: "AuthorizedResource",
      resourceId: resource.id,
      metadata: { targetId, resourceType: resource.resourceType, provenance: resource.provenance },
    });
    return resource;
  }

  async listTestCases(workspaceId: string, targetId: string) {
    await this.assertTarget(workspaceId, targetId);
    const cases = await this.prisma.authorizationTestCase.findMany({
      where: { workspaceId, targetId },
      include: { resource: true },
      orderBy: { createdAt: "desc" },
    });
    return cases.map(({ encryptedRequestBody, ...testCase }) => ({
      ...testCase,
      requestBodyConfigured: encryptedRequestBody !== null,
    }));
  }

  async createTestCase(
    workspaceId: string,
    targetId: string,
    actorId: string,
    input: {
      name: string;
      resourceId: string;
      action: string;
      endpointTemplate: string;
      method: "GET" | "HEAD" | "OPTIONS" | "POST" | "PUT" | "PATCH" | "DELETE";
      identityIds: string[];
      expectedPolicy: Record<string, "ALLOW" | "DENY" | "UNKNOWN">;
      mutationRisk: "READ_ONLY" | "SAFE_IDEMPOTENT" | "DISPOSABLE_TEST_FIXTURE";
      mutationExplicitlyAuthorized: boolean;
      cleanupStrategy: "NONE" | "DELETE_CREATED_RESOURCE" | "RESTORE_FIXTURE" | "CUSTOM";
      requestHeaders?: Record<string, string>;
      requestBody?: string;
      contentType?: string;
      followRedirects: boolean;
      timingSamples: number;
    },
  ) {
    const target = await this.assertTarget(workspaceId, targetId);
    const resource = await this.prisma.authorizedResource.findFirst({
      where: { id: input.resourceId, workspaceId, targetId, enabled: true },
    });
    if (!resource)
      throw new BadRequestException("Test case resource is not approved for this target.");
    const identityIds = [...new Set(input.identityIds)];
    const identityCount = await this.prisma.assessmentIdentity.count({
      where: { id: { in: identityIds }, workspaceId, targetId, enabled: true },
    });
    if (identityIds.length < 2 || identityCount !== identityIds.length) {
      throw new BadRequestException(
        "Test cases require at least two enabled identities on this target.",
      );
    }
    if (Object.keys(input.expectedPolicy).some((id) => !identityIds.includes(id))) {
      throw new BadRequestException(
        "Expected policy references an identity outside the test case.",
      );
    }
    if (Object.keys(input.requestHeaders ?? {}).some((name) => protectedHeader.test(name))) {
      throw new BadRequestException("Test-case headers cannot override identity authentication.");
    }
    const renderedForValidation = input.endpointTemplate.replace(
      /\{[A-Za-z][A-Za-z0-9_]*\}/gu,
      "fixture",
    );
    let endpoint: URL;
    try {
      endpoint = new URL(renderedForValidation);
    } catch {
      throw new BadRequestException("Endpoint template must be an absolute HTTP(S) URL.");
    }
    if (!["http:", "https:"].includes(endpoint.protocol))
      throw new BadRequestException("Endpoint scheme is not permitted.");
    const targetOrigin = new URL(target.origin);
    const exactHost = endpoint.hostname === targetOrigin.hostname;
    const subdomain =
      target.includeSubdomains && endpoint.hostname.endsWith(`.${targetOrigin.hostname}`);
    if (!exactHost && !subdomain)
      throw new BadRequestException("Endpoint template is outside the target host scope.");
    const mutating = !["GET", "HEAD", "OPTIONS"].includes(input.method);
    if (
      mutating &&
      (!input.mutationExplicitlyAuthorized ||
        input.mutationRisk !== "DISPOSABLE_TEST_FIXTURE" ||
        input.cleanupStrategy === "NONE")
    )
      throw new BadRequestException(
        "Mutation requires explicit disposable-fixture authorization and cleanup.",
      );
    const encryptedRequestBody =
      input.requestBody === undefined
        ? null
        : encryptCredential(
            { type: "CUSTOM_HEADERS", headers: { "x-encrypted-request-body": input.requestBody } },
            encryptionKey(),
          );
    const testCase = await this.prisma.authorizationTestCase.create({
      data: {
        workspaceId,
        targetId,
        resourceId: input.resourceId,
        name: input.name.trim(),
        action: input.action.trim(),
        endpointTemplate: input.endpointTemplate,
        method: input.method,
        identityIds,
        expectedPolicy: input.expectedPolicy,
        mutationRisk: input.mutationRisk,
        mutationExplicitlyAuthorized: input.mutationExplicitlyAuthorized,
        cleanupStrategy: input.cleanupStrategy,
        requestHeaders: (input.requestHeaders ?? {}) as Prisma.InputJsonValue,
        encryptedRequestBody: encryptedRequestBody as unknown as Prisma.InputJsonValue,
        contentType: input.contentType ?? null,
        followRedirects: input.followRedirects,
        timingSamples: input.timingSamples,
      },
    });
    await this.audit.record({
      workspaceId,
      actorId,
      action: "authorization_test_case.created",
      resourceType: "AuthorizationTestCase",
      resourceId: testCase.id,
      metadata: {
        targetId,
        resourceId: input.resourceId,
        method: input.method,
        identityCount: identityIds.length,
        mutationRisk: input.mutationRisk,
      },
    });
    const { encryptedRequestBody: storedRequestBody, ...safe } = testCase;
    return { ...safe, requestBodyConfigured: storedRequestBody !== null };
  }

  async matrix(workspaceId: string, scanId: string) {
    const scan = await this.prisma.scan.findFirst({
      where: { id: scanId, workspaceId },
      select: { id: true },
    });
    if (!scan) throw new NotFoundException("Scan does not exist in this workspace.");
    return this.prisma.authorizationTestResult.findMany({
      where: { workspaceId, scanId },
      include: {
        testCase: { select: { id: true, name: true, method: true, endpointTemplate: true } },
      },
      orderBy: { createdAt: "asc" },
    });
  }

  private async assertTarget(workspaceId: string, targetId: string) {
    const target = await this.prisma.target.findFirst({ where: { id: targetId, workspaceId } });
    if (!target) throw new NotFoundException("Target does not exist in this workspace.");
    return target;
  }
}
