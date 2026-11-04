ALTER TYPE "ScanState" ADD VALUE IF NOT EXISTS 'AUTHORIZATION_ANALYSIS' BEFORE 'NORMALIZING';

CREATE TYPE "IdentityAuthenticationType" AS ENUM (
  'ANONYMOUS', 'USERNAME_PASSWORD', 'SESSION_COOKIE', 'BEARER_TOKEN',
  'API_KEY', 'CUSTOM_HEADERS', 'OAUTH_OIDC', 'LOGIN_AUTOMATION'
);
CREATE TYPE "IdentityAuthenticationState" AS ENUM (
  'AUTHENTICATED', 'AUTH_EXPIRED', 'AUTH_REFRESHING', 'AUTH_FAILED',
  'LOGGED_OUT', 'UNKNOWN', 'UNAVAILABLE'
);
CREATE TYPE "ResourceProvenance" AS ENUM (
  'OPERATOR_SUPPLIED', 'SCANNER_CREATED', 'APPROVED_SEED', 'IDENTITY_OBSERVED'
);
CREATE TYPE "ResourceRelationshipType" AS ENUM (
  'OWNS', 'MEMBER_OF', 'ADMIN_OF', 'MANAGER_OF', 'BELONGS_TO_TENANT', 'SHARED_WITH'
);
CREATE TYPE "AuthorizationMutationRisk" AS ENUM (
  'READ_ONLY', 'SAFE_IDEMPOTENT', 'DISPOSABLE_TEST_FIXTURE'
);
CREATE TYPE "AuthorizationCleanupStrategy" AS ENUM (
  'NONE', 'DELETE_CREATED_RESOURCE', 'RESTORE_FIXTURE', 'CUSTOM'
);

CREATE TABLE "AssessmentIdentity" (
  "id" TEXT NOT NULL,
  "workspaceId" TEXT NOT NULL,
  "targetId" TEXT NOT NULL,
  "label" TEXT NOT NULL,
  "role" TEXT NOT NULL,
  "tenant" TEXT,
  "authenticationType" "IdentityAuthenticationType" NOT NULL,
  "authenticationState" "IdentityAuthenticationState" NOT NULL DEFAULT 'UNKNOWN',
  "encryptedCredential" JSONB,
  "credentialFingerprint" TEXT,
  "metadata" JSONB,
  "enabled" BOOLEAN NOT NULL DEFAULT true,
  "lastAuthenticatedAt" TIMESTAMP(3),
  "lastFailureReason" TEXT,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "AssessmentIdentity_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "AuthorizedResource" (
  "id" TEXT NOT NULL,
  "workspaceId" TEXT NOT NULL,
  "targetId" TEXT NOT NULL,
  "resourceType" TEXT NOT NULL,
  "externalId" TEXT NOT NULL,
  "tenant" TEXT,
  "ownerIdentityId" TEXT,
  "provenance" "ResourceProvenance" NOT NULL,
  "endpointVariables" JSONB,
  "metadata" JSONB,
  "enabled" BOOLEAN NOT NULL DEFAULT true,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "AuthorizedResource_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "ResourceIdentityRelationship" (
  "id" TEXT NOT NULL,
  "resourceId" TEXT NOT NULL,
  "identityId" TEXT NOT NULL,
  "relationship" "ResourceRelationshipType" NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "ResourceIdentityRelationship_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "AuthorizationTestCase" (
  "id" TEXT NOT NULL,
  "workspaceId" TEXT NOT NULL,
  "targetId" TEXT NOT NULL,
  "resourceId" TEXT NOT NULL,
  "name" TEXT NOT NULL,
  "action" TEXT NOT NULL,
  "endpointTemplate" TEXT NOT NULL,
  "method" TEXT NOT NULL,
  "identityIds" TEXT[] NOT NULL,
  "expectedPolicy" JSONB NOT NULL,
  "mutationRisk" "AuthorizationMutationRisk" NOT NULL DEFAULT 'READ_ONLY',
  "mutationExplicitlyAuthorized" BOOLEAN NOT NULL DEFAULT false,
  "cleanupStrategy" "AuthorizationCleanupStrategy" NOT NULL DEFAULT 'NONE',
  "requestHeaders" JSONB,
  "encryptedRequestBody" JSONB,
  "contentType" TEXT,
  "followRedirects" BOOLEAN NOT NULL DEFAULT false,
  "timingSamples" INTEGER NOT NULL DEFAULT 1,
  "enabled" BOOLEAN NOT NULL DEFAULT true,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "AuthorizationTestCase_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "AuthorizationTestResult" (
  "id" TEXT NOT NULL,
  "workspaceId" TEXT NOT NULL,
  "scanId" TEXT NOT NULL,
  "testCaseId" TEXT NOT NULL,
  "correlationId" TEXT NOT NULL,
  "matrix" JSONB NOT NULL,
  "findingFingerprints" TEXT[] NOT NULL,
  "incompleteIdentityIds" TEXT[] NOT NULL,
  "degraded" BOOLEAN NOT NULL DEFAULT false,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "AuthorizationTestResult_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "AssessmentIdentity_targetId_label_key" ON "AssessmentIdentity"("targetId", "label");
CREATE INDEX "AssessmentIdentity_workspaceId_targetId_enabled_idx" ON "AssessmentIdentity"("workspaceId", "targetId", "enabled");
CREATE INDEX "AssessmentIdentity_workspaceId_tenant_role_idx" ON "AssessmentIdentity"("workspaceId", "tenant", "role");
CREATE UNIQUE INDEX "AuthorizedResource_targetId_resourceType_externalId_key" ON "AuthorizedResource"("targetId", "resourceType", "externalId");
CREATE INDEX "AuthorizedResource_workspaceId_targetId_enabled_idx" ON "AuthorizedResource"("workspaceId", "targetId", "enabled");
CREATE INDEX "AuthorizedResource_ownerIdentityId_idx" ON "AuthorizedResource"("ownerIdentityId");
CREATE UNIQUE INDEX "ResourceIdentityRelationship_resourceId_identityId_relationship_key" ON "ResourceIdentityRelationship"("resourceId", "identityId", "relationship");
CREATE INDEX "ResourceIdentityRelationship_identityId_relationship_idx" ON "ResourceIdentityRelationship"("identityId", "relationship");
CREATE UNIQUE INDEX "AuthorizationTestCase_targetId_name_key" ON "AuthorizationTestCase"("targetId", "name");
CREATE INDEX "AuthorizationTestCase_workspaceId_targetId_enabled_idx" ON "AuthorizationTestCase"("workspaceId", "targetId", "enabled");
CREATE INDEX "AuthorizationTestCase_resourceId_idx" ON "AuthorizationTestCase"("resourceId");
CREATE UNIQUE INDEX "AuthorizationTestResult_scanId_testCaseId_key" ON "AuthorizationTestResult"("scanId", "testCaseId");
CREATE INDEX "AuthorizationTestResult_workspaceId_scanId_idx" ON "AuthorizationTestResult"("workspaceId", "scanId");
CREATE INDEX "AuthorizationTestResult_correlationId_idx" ON "AuthorizationTestResult"("correlationId");

ALTER TABLE "AssessmentIdentity" ADD CONSTRAINT "AssessmentIdentity_workspaceId_fkey" FOREIGN KEY ("workspaceId") REFERENCES "Workspace"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "AssessmentIdentity" ADD CONSTRAINT "AssessmentIdentity_targetId_fkey" FOREIGN KEY ("targetId") REFERENCES "Target"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "AuthorizedResource" ADD CONSTRAINT "AuthorizedResource_workspaceId_fkey" FOREIGN KEY ("workspaceId") REFERENCES "Workspace"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "AuthorizedResource" ADD CONSTRAINT "AuthorizedResource_targetId_fkey" FOREIGN KEY ("targetId") REFERENCES "Target"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "AuthorizedResource" ADD CONSTRAINT "AuthorizedResource_ownerIdentityId_fkey" FOREIGN KEY ("ownerIdentityId") REFERENCES "AssessmentIdentity"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "ResourceIdentityRelationship" ADD CONSTRAINT "ResourceIdentityRelationship_resourceId_fkey" FOREIGN KEY ("resourceId") REFERENCES "AuthorizedResource"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "ResourceIdentityRelationship" ADD CONSTRAINT "ResourceIdentityRelationship_identityId_fkey" FOREIGN KEY ("identityId") REFERENCES "AssessmentIdentity"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "AuthorizationTestCase" ADD CONSTRAINT "AuthorizationTestCase_workspaceId_fkey" FOREIGN KEY ("workspaceId") REFERENCES "Workspace"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "AuthorizationTestCase" ADD CONSTRAINT "AuthorizationTestCase_targetId_fkey" FOREIGN KEY ("targetId") REFERENCES "Target"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "AuthorizationTestCase" ADD CONSTRAINT "AuthorizationTestCase_resourceId_fkey" FOREIGN KEY ("resourceId") REFERENCES "AuthorizedResource"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "AuthorizationTestResult" ADD CONSTRAINT "AuthorizationTestResult_workspaceId_fkey" FOREIGN KEY ("workspaceId") REFERENCES "Workspace"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "AuthorizationTestResult" ADD CONSTRAINT "AuthorizationTestResult_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "AuthorizationTestResult" ADD CONSTRAINT "AuthorizationTestResult_testCaseId_fkey" FOREIGN KEY ("testCaseId") REFERENCES "AuthorizationTestCase"("id") ON DELETE CASCADE ON UPDATE CASCADE;
