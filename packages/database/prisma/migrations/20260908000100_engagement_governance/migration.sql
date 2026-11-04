BEGIN;
-- CreateEnum
CREATE TYPE "EngagementState" AS ENUM ('DRAFT', 'SCOPING', 'AWAITING_AUTHORIZATION', 'AUTHORIZED', 'SCHEDULED', 'ACTIVE', 'TESTING', 'INTERNAL_REVIEW', 'CLIENT_REVIEW', 'REMEDIATION', 'RETEST', 'COMPLETED', 'ARCHIVED');

-- CreateEnum
CREATE TYPE "ActionRisk" AS ENUM ('PASSIVE', 'SAFE', 'LOW_IMPACT', 'MODERATE_IMPACT', 'HIGH_IMPACT', 'RESTRICTED');

-- CreateEnum
CREATE TYPE "TestCategory" AS ENUM ('DISCOVERY', 'HTTP_CONFIGURATION', 'AUTHORIZATION');

-- CreateEnum
CREATE TYPE "AssetEnvironment" AS ENUM ('PRODUCTION', 'STAGING', 'DEVELOPMENT', 'LAB');

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "WorkspaceRole" ADD VALUE 'PLATFORM_ADMIN';
ALTER TYPE "WorkspaceRole" ADD VALUE 'ORG_OWNER';
ALTER TYPE "WorkspaceRole" ADD VALUE 'SECURITY_DIRECTOR';
ALTER TYPE "WorkspaceRole" ADD VALUE 'PENTEST_MANAGER';
ALTER TYPE "WorkspaceRole" ADD VALUE 'LEAD_PENTESTER';
ALTER TYPE "WorkspaceRole" ADD VALUE 'PENTESTER';
ALTER TYPE "WorkspaceRole" ADD VALUE 'JUNIOR_PENTESTER';
ALTER TYPE "WorkspaceRole" ADD VALUE 'REVIEWER';
ALTER TYPE "WorkspaceRole" ADD VALUE 'CLIENT_ADMIN';
ALTER TYPE "WorkspaceRole" ADD VALUE 'CLIENT_USER';

-- DropForeignKey
ALTER TABLE "ScopeRule" DROP CONSTRAINT "ScopeRule_targetId_fkey";

-- DropForeignKey
ALTER TABLE "Scan" DROP CONSTRAINT "Scan_targetId_fkey";

-- DropForeignKey
ALTER TABLE "AssessmentIdentity" DROP CONSTRAINT "AssessmentIdentity_targetId_fkey";

-- DropForeignKey
ALTER TABLE "AuthorizedResource" DROP CONSTRAINT "AuthorizedResource_targetId_fkey";

-- DropForeignKey
ALTER TABLE "AuthorizedResource" DROP CONSTRAINT "AuthorizedResource_ownerIdentityId_fkey";

-- DropForeignKey
ALTER TABLE "AuthorizationTestCase" DROP CONSTRAINT "AuthorizationTestCase_targetId_fkey";

-- DropForeignKey
ALTER TABLE "AuthorizationTestCase" DROP CONSTRAINT "AuthorizationTestCase_resourceId_fkey";

-- DropForeignKey
ALTER TABLE "AuthorizationTestResult" DROP CONSTRAINT "AuthorizationTestResult_scanId_fkey";

-- DropForeignKey
ALTER TABLE "ScanStage" DROP CONSTRAINT "ScanStage_scanId_fkey";

-- DropForeignKey
ALTER TABLE "ScanJob" DROP CONSTRAINT "ScanJob_scanId_fkey";

-- DropForeignKey
ALTER TABLE "DiscoveredAsset" DROP CONSTRAINT "DiscoveredAsset_scanId_fkey";

-- DropForeignKey
ALTER TABLE "DiscoveredURL" DROP CONSTRAINT "DiscoveredURL_scanId_fkey";

-- DropForeignKey
ALTER TABLE "DiscoveredEndpoint" DROP CONSTRAINT "DiscoveredEndpoint_scanId_fkey";

-- DropForeignKey
ALTER TABLE "DiscoveredParameter" DROP CONSTRAINT "DiscoveredParameter_scanId_fkey";

-- DropForeignKey
ALTER TABLE "DiscoveredParameter" DROP CONSTRAINT "DiscoveredParameter_endpointId_fkey";

-- DropForeignKey
ALTER TABLE "Technology" DROP CONSTRAINT "Technology_scanId_fkey";

-- DropForeignKey
ALTER TABLE "ScannerObservation" DROP CONSTRAINT "ScannerObservation_scanId_fkey";

-- DropForeignKey
ALTER TABLE "Evidence" DROP CONSTRAINT "Evidence_scanId_fkey";

-- DropForeignKey
ALTER TABLE "Evidence" DROP CONSTRAINT "Evidence_observationId_fkey";

-- DropForeignKey
ALTER TABLE "Finding" DROP CONSTRAINT "Finding_scanId_fkey";

-- DropForeignKey
ALTER TABLE "ScanComparison" DROP CONSTRAINT "ScanComparison_scanId_fkey";

-- DropForeignKey
ALTER TABLE "AIAnalysis" DROP CONSTRAINT "AIAnalysis_scanId_fkey";

-- DropForeignKey
ALTER TABLE "AIAnalysis" DROP CONSTRAINT "AIAnalysis_findingId_fkey";

-- DropForeignKey
ALTER TABLE "Report" DROP CONSTRAINT "Report_scanId_fkey";

-- DropForeignKey
ALTER TABLE "Report" DROP CONSTRAINT "Report_findingId_fkey";

-- AlterTable
ALTER TABLE "Workspace" ADD COLUMN     "organizationId" TEXT;

-- AlterTable
ALTER TABLE "Target" ADD COLUMN     "scopeRevision" INTEGER NOT NULL DEFAULT 1;

-- AlterTable
ALTER TABLE "Scan" ADD COLUMN     "authorizationGrantId" TEXT,
ADD COLUMN     "engagementId" TEXT,
ADD COLUMN     "executionActorId" TEXT;

-- CreateTable
CREATE TABLE "Organization" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Organization_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "OrganizationMember" (
    "organizationId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "role" "WorkspaceRole" NOT NULL,

    CONSTRAINT "OrganizationMember_pkey" PRIMARY KEY ("organizationId","userId")
);

-- CreateTable
CREATE TABLE "Client" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "legalName" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Client_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Engagement" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "objective" TEXT NOT NULL,
    "environment" "AssetEnvironment" NOT NULL,
    "state" "EngagementState" NOT NULL DEFAULT 'DRAFT',
    "version" INTEGER NOT NULL DEFAULT 1,
    "policyRevision" INTEGER NOT NULL DEFAULT 0,
    "requestsMade" INTEGER NOT NULL DEFAULT 0,
    "nextRequestAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Engagement_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EngagementPolicy" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "engagementId" TEXT NOT NULL,
    "revision" INTEGER NOT NULL,
    "windowStartsAt" TIMESTAMP(3) NOT NULL,
    "windowEndsAt" TIMESTAMP(3) NOT NULL,
    "maxRequests" INTEGER NOT NULL,
    "requestsPerSecond" DOUBLE PRECISION NOT NULL,
    "maxConcurrency" INTEGER NOT NULL,
    "maxRisk" "ActionRisk" NOT NULL,
    "allowedCategories" "TestCategory"[],
    "allowedProtocols" TEXT[],
    "restrictions" TEXT NOT NULL,
    "createdById" TEXT NOT NULL,
    "reason" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "EngagementPolicy_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EngagementTarget" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "engagementId" TEXT NOT NULL,
    "policyRevision" INTEGER NOT NULL,
    "targetId" TEXT NOT NULL,
    "scopeRevision" INTEGER NOT NULL,
    "scopeDigest" TEXT NOT NULL,

    CONSTRAINT "EngagementTarget_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuthorizationDocument" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "engagementId" TEXT NOT NULL,
    "filename" TEXT NOT NULL,
    "contentType" TEXT NOT NULL,
    "byteLength" INTEGER NOT NULL,
    "sha256" TEXT NOT NULL,
    "encryptedContent" BYTEA NOT NULL,
    "uploadedById" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AuthorizationDocument_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuthorizationGrant" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "engagementId" TEXT NOT NULL,
    "policyRevision" INTEGER NOT NULL,
    "documentId" TEXT NOT NULL,
    "authorizedBy" TEXT NOT NULL,
    "approvedById" TEXT NOT NULL,
    "validFrom" TIMESTAMP(3) NOT NULL,
    "validUntil" TIMESTAMP(3) NOT NULL,
    "reason" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AuthorizationGrant_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuthorizationRevocation" (
    "id" TEXT NOT NULL,
    "grantId" TEXT NOT NULL,
    "actorId" TEXT NOT NULL,
    "reason" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AuthorizationRevocation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EngagementTransition" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "engagementId" TEXT NOT NULL,
    "fromState" "EngagementState" NOT NULL,
    "toState" "EngagementState" NOT NULL,
    "actorId" TEXT NOT NULL,
    "authorizationBasis" TEXT NOT NULL,
    "grantId" TEXT,
    "version" INTEGER NOT NULL,
    "reason" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "EngagementTransition_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ExecutionDecision" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "engagementId" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "actorId" TEXT NOT NULL,
    "grantId" TEXT,
    "policyRevision" INTEGER NOT NULL,
    "tool" TEXT NOT NULL,
    "phase" TEXT NOT NULL,
    "method" TEXT NOT NULL,
    "destination" TEXT NOT NULL,
    "risk" "ActionRisk" NOT NULL,
    "permitted" BOOLEAN NOT NULL,
    "code" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ExecutionDecision_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "OrganizationMember_userId_idx" ON "OrganizationMember"("userId");

-- CreateIndex
CREATE INDEX "Client_workspaceId_createdAt_id_idx" ON "Client"("workspaceId", "createdAt", "id");

-- CreateIndex
CREATE UNIQUE INDEX "Client_workspaceId_id_key" ON "Client"("workspaceId", "id");

-- CreateIndex
CREATE INDEX "Engagement_workspaceId_state_createdAt_id_idx" ON "Engagement"("workspaceId", "state", "createdAt", "id");

-- CreateIndex
CREATE INDEX "Engagement_workspaceId_clientId_idx" ON "Engagement"("workspaceId", "clientId");

-- CreateIndex
CREATE UNIQUE INDEX "Engagement_workspaceId_id_key" ON "Engagement"("workspaceId", "id");

-- CreateIndex
CREATE UNIQUE INDEX "EngagementPolicy_workspaceId_engagementId_revision_key" ON "EngagementPolicy"("workspaceId", "engagementId", "revision");

-- CreateIndex
CREATE INDEX "EngagementTarget_workspaceId_targetId_idx" ON "EngagementTarget"("workspaceId", "targetId");

-- CreateIndex
CREATE UNIQUE INDEX "EngagementTarget_workspaceId_engagementId_policyRevision_ta_key" ON "EngagementTarget"("workspaceId", "engagementId", "policyRevision", "targetId");

-- CreateIndex
CREATE INDEX "AuthorizationDocument_workspaceId_engagementId_createdAt_idx" ON "AuthorizationDocument"("workspaceId", "engagementId", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "AuthorizationDocument_workspaceId_engagementId_id_key" ON "AuthorizationDocument"("workspaceId", "engagementId", "id");

-- CreateIndex
CREATE INDEX "AuthorizationGrant_workspaceId_engagementId_policyRevision__idx" ON "AuthorizationGrant"("workspaceId", "engagementId", "policyRevision", "validUntil");

-- CreateIndex
CREATE UNIQUE INDEX "AuthorizationGrant_workspaceId_engagementId_id_key" ON "AuthorizationGrant"("workspaceId", "engagementId", "id");

-- CreateIndex
CREATE UNIQUE INDEX "AuthorizationRevocation_grantId_key" ON "AuthorizationRevocation"("grantId");

-- CreateIndex
CREATE UNIQUE INDEX "EngagementTransition_workspaceId_engagementId_version_key" ON "EngagementTransition"("workspaceId", "engagementId", "version");

-- CreateIndex
CREATE INDEX "ExecutionDecision_workspaceId_engagementId_createdAt_id_idx" ON "ExecutionDecision"("workspaceId", "engagementId", "createdAt", "id");

-- CreateIndex
CREATE INDEX "ExecutionDecision_workspaceId_scanId_createdAt_idx" ON "ExecutionDecision"("workspaceId", "scanId", "createdAt");

-- CreateIndex
CREATE INDEX "Workspace_organizationId_idx" ON "Workspace"("organizationId");

-- CreateIndex
CREATE UNIQUE INDEX "Target_workspaceId_id_key" ON "Target"("workspaceId", "id");

-- CreateIndex
CREATE INDEX "Scan_workspaceId_engagementId_createdAt_idx" ON "Scan"("workspaceId", "engagementId", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "Scan_workspaceId_id_key" ON "Scan"("workspaceId", "id");

-- CreateIndex
CREATE UNIQUE INDEX "AssessmentIdentity_workspaceId_id_key" ON "AssessmentIdentity"("workspaceId", "id");

-- CreateIndex
CREATE UNIQUE INDEX "AssessmentIdentity_workspaceId_targetId_id_key" ON "AssessmentIdentity"("workspaceId", "targetId", "id");

-- CreateIndex
CREATE UNIQUE INDEX "AuthorizedResource_workspaceId_id_key" ON "AuthorizedResource"("workspaceId", "id");

-- CreateIndex
CREATE UNIQUE INDEX "AuthorizedResource_workspaceId_targetId_id_key" ON "AuthorizedResource"("workspaceId", "targetId", "id");

-- CreateIndex
CREATE UNIQUE INDEX "AuthorizationTestCase_workspaceId_id_key" ON "AuthorizationTestCase"("workspaceId", "id");

-- CreateIndex
CREATE UNIQUE INDEX "AuthorizationTestCase_workspaceId_targetId_id_key" ON "AuthorizationTestCase"("workspaceId", "targetId", "id");

-- CreateIndex
CREATE UNIQUE INDEX "DiscoveredEndpoint_workspaceId_id_key" ON "DiscoveredEndpoint"("workspaceId", "id");

-- CreateIndex
CREATE UNIQUE INDEX "DiscoveredEndpoint_workspaceId_scanId_id_key" ON "DiscoveredEndpoint"("workspaceId", "scanId", "id");

-- CreateIndex
CREATE UNIQUE INDEX "ScannerObservation_workspaceId_id_key" ON "ScannerObservation"("workspaceId", "id");

-- CreateIndex
CREATE UNIQUE INDEX "ScannerObservation_workspaceId_scanId_id_key" ON "ScannerObservation"("workspaceId", "scanId", "id");

-- CreateIndex
CREATE UNIQUE INDEX "Evidence_workspaceId_id_key" ON "Evidence"("workspaceId", "id");

-- CreateIndex
CREATE UNIQUE INDEX "Evidence_workspaceId_scanId_id_key" ON "Evidence"("workspaceId", "scanId", "id");

-- CreateIndex
CREATE UNIQUE INDEX "Finding_workspaceId_id_key" ON "Finding"("workspaceId", "id");

-- CreateIndex
CREATE UNIQUE INDEX "Finding_workspaceId_scanId_id_key" ON "Finding"("workspaceId", "scanId", "id");

-- CreateIndex
CREATE UNIQUE INDEX "ScanComparison_workspaceId_scanId_key" ON "ScanComparison"("workspaceId", "scanId");

-- Each legacy workspace remains isolated in its own organization. No authorization is invented.
INSERT INTO "Organization" (id, name, "createdAt") SELECT 'org_' || id, name, "createdAt" FROM "Workspace";
UPDATE "Workspace" SET "organizationId" = 'org_' || id;
INSERT INTO "OrganizationMember" ("organizationId", "userId", role)
SELECT w."organizationId", m."userId", r.name FROM "WorkspaceMember" m
JOIN "Workspace" w ON w.id = m."workspaceId" JOIN "Role" r ON r.id = m."roleId";
ALTER TABLE "Workspace" ALTER COLUMN "organizationId" SET NOT NULL;

-- AddForeignKey
ALTER TABLE "Workspace" ADD CONSTRAINT "Workspace_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScopeRule" ADD CONSTRAINT "ScopeRule_workspaceId_targetId_fkey" FOREIGN KEY ("workspaceId", "targetId") REFERENCES "Target"("workspaceId", "id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Scan" ADD CONSTRAINT "Scan_workspaceId_engagementId_fkey" FOREIGN KEY ("workspaceId", "engagementId") REFERENCES "Engagement"("workspaceId", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Scan" ADD CONSTRAINT "Scan_workspaceId_engagementId_authorizationGrantId_fkey" FOREIGN KEY ("workspaceId", "engagementId", "authorizationGrantId") REFERENCES "AuthorizationGrant"("workspaceId", "engagementId", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Scan" ADD CONSTRAINT "Scan_workspaceId_targetId_fkey" FOREIGN KEY ("workspaceId", "targetId") REFERENCES "Target"("workspaceId", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AssessmentIdentity" ADD CONSTRAINT "AssessmentIdentity_workspaceId_targetId_fkey" FOREIGN KEY ("workspaceId", "targetId") REFERENCES "Target"("workspaceId", "id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuthorizedResource" ADD CONSTRAINT "AuthorizedResource_workspaceId_targetId_fkey" FOREIGN KEY ("workspaceId", "targetId") REFERENCES "Target"("workspaceId", "id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuthorizedResource" ADD CONSTRAINT "AuthorizedResource_workspaceId_targetId_ownerIdentityId_fkey" FOREIGN KEY ("workspaceId", "targetId", "ownerIdentityId") REFERENCES "AssessmentIdentity"("workspaceId", "targetId", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuthorizationTestCase" ADD CONSTRAINT "AuthorizationTestCase_workspaceId_targetId_fkey" FOREIGN KEY ("workspaceId", "targetId") REFERENCES "Target"("workspaceId", "id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuthorizationTestCase" ADD CONSTRAINT "AuthorizationTestCase_workspaceId_targetId_resourceId_fkey" FOREIGN KEY ("workspaceId", "targetId", "resourceId") REFERENCES "AuthorizedResource"("workspaceId", "targetId", "id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuthorizationTestResult" ADD CONSTRAINT "AuthorizationTestResult_workspaceId_scanId_fkey" FOREIGN KEY ("workspaceId", "scanId") REFERENCES "Scan"("workspaceId", "id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScanStage" ADD CONSTRAINT "ScanStage_workspaceId_scanId_fkey" FOREIGN KEY ("workspaceId", "scanId") REFERENCES "Scan"("workspaceId", "id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScanJob" ADD CONSTRAINT "ScanJob_workspaceId_scanId_fkey" FOREIGN KEY ("workspaceId", "scanId") REFERENCES "Scan"("workspaceId", "id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DiscoveredAsset" ADD CONSTRAINT "DiscoveredAsset_workspaceId_scanId_fkey" FOREIGN KEY ("workspaceId", "scanId") REFERENCES "Scan"("workspaceId", "id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DiscoveredURL" ADD CONSTRAINT "DiscoveredURL_workspaceId_scanId_fkey" FOREIGN KEY ("workspaceId", "scanId") REFERENCES "Scan"("workspaceId", "id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DiscoveredEndpoint" ADD CONSTRAINT "DiscoveredEndpoint_workspaceId_scanId_fkey" FOREIGN KEY ("workspaceId", "scanId") REFERENCES "Scan"("workspaceId", "id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DiscoveredParameter" ADD CONSTRAINT "DiscoveredParameter_workspaceId_scanId_fkey" FOREIGN KEY ("workspaceId", "scanId") REFERENCES "Scan"("workspaceId", "id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DiscoveredParameter" ADD CONSTRAINT "DiscoveredParameter_workspaceId_scanId_endpointId_fkey" FOREIGN KEY ("workspaceId", "scanId", "endpointId") REFERENCES "DiscoveredEndpoint"("workspaceId", "scanId", "id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Technology" ADD CONSTRAINT "Technology_workspaceId_scanId_fkey" FOREIGN KEY ("workspaceId", "scanId") REFERENCES "Scan"("workspaceId", "id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScannerObservation" ADD CONSTRAINT "ScannerObservation_workspaceId_scanId_fkey" FOREIGN KEY ("workspaceId", "scanId") REFERENCES "Scan"("workspaceId", "id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Evidence" ADD CONSTRAINT "Evidence_workspaceId_scanId_fkey" FOREIGN KEY ("workspaceId", "scanId") REFERENCES "Scan"("workspaceId", "id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Evidence" ADD CONSTRAINT "Evidence_workspaceId_scanId_observationId_fkey" FOREIGN KEY ("workspaceId", "scanId", "observationId") REFERENCES "ScannerObservation"("workspaceId", "scanId", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Finding" ADD CONSTRAINT "Finding_workspaceId_scanId_fkey" FOREIGN KEY ("workspaceId", "scanId") REFERENCES "Scan"("workspaceId", "id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScanComparison" ADD CONSTRAINT "ScanComparison_workspaceId_scanId_fkey" FOREIGN KEY ("workspaceId", "scanId") REFERENCES "Scan"("workspaceId", "id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AIAnalysis" ADD CONSTRAINT "AIAnalysis_workspaceId_scanId_fkey" FOREIGN KEY ("workspaceId", "scanId") REFERENCES "Scan"("workspaceId", "id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AIAnalysis" ADD CONSTRAINT "AIAnalysis_workspaceId_scanId_findingId_fkey" FOREIGN KEY ("workspaceId", "scanId", "findingId") REFERENCES "Finding"("workspaceId", "scanId", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Report" ADD CONSTRAINT "Report_workspaceId_scanId_fkey" FOREIGN KEY ("workspaceId", "scanId") REFERENCES "Scan"("workspaceId", "id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Report" ADD CONSTRAINT "Report_workspaceId_scanId_findingId_fkey" FOREIGN KEY ("workspaceId", "scanId", "findingId") REFERENCES "Finding"("workspaceId", "scanId", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "OrganizationMember" ADD CONSTRAINT "OrganizationMember_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "OrganizationMember" ADD CONSTRAINT "OrganizationMember_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Client" ADD CONSTRAINT "Client_workspaceId_fkey" FOREIGN KEY ("workspaceId") REFERENCES "Workspace"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Engagement" ADD CONSTRAINT "Engagement_workspaceId_fkey" FOREIGN KEY ("workspaceId") REFERENCES "Workspace"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Engagement" ADD CONSTRAINT "Engagement_workspaceId_clientId_fkey" FOREIGN KEY ("workspaceId", "clientId") REFERENCES "Client"("workspaceId", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EngagementPolicy" ADD CONSTRAINT "EngagementPolicy_workspaceId_engagementId_fkey" FOREIGN KEY ("workspaceId", "engagementId") REFERENCES "Engagement"("workspaceId", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EngagementTarget" ADD CONSTRAINT "EngagementTarget_workspaceId_engagementId_policyRevision_fkey" FOREIGN KEY ("workspaceId", "engagementId", "policyRevision") REFERENCES "EngagementPolicy"("workspaceId", "engagementId", "revision") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EngagementTarget" ADD CONSTRAINT "EngagementTarget_workspaceId_targetId_fkey" FOREIGN KEY ("workspaceId", "targetId") REFERENCES "Target"("workspaceId", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuthorizationDocument" ADD CONSTRAINT "AuthorizationDocument_workspaceId_engagementId_fkey" FOREIGN KEY ("workspaceId", "engagementId") REFERENCES "Engagement"("workspaceId", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuthorizationGrant" ADD CONSTRAINT "AuthorizationGrant_workspaceId_engagementId_fkey" FOREIGN KEY ("workspaceId", "engagementId") REFERENCES "Engagement"("workspaceId", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuthorizationGrant" ADD CONSTRAINT "AuthorizationGrant_workspaceId_engagementId_policyRevision_fkey" FOREIGN KEY ("workspaceId", "engagementId", "policyRevision") REFERENCES "EngagementPolicy"("workspaceId", "engagementId", "revision") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuthorizationGrant" ADD CONSTRAINT "AuthorizationGrant_workspaceId_engagementId_documentId_fkey" FOREIGN KEY ("workspaceId", "engagementId", "documentId") REFERENCES "AuthorizationDocument"("workspaceId", "engagementId", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuthorizationRevocation" ADD CONSTRAINT "AuthorizationRevocation_grantId_fkey" FOREIGN KEY ("grantId") REFERENCES "AuthorizationGrant"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EngagementTransition" ADD CONSTRAINT "EngagementTransition_workspaceId_engagementId_fkey" FOREIGN KEY ("workspaceId", "engagementId") REFERENCES "Engagement"("workspaceId", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ExecutionDecision" ADD CONSTRAINT "ExecutionDecision_workspaceId_engagementId_fkey" FOREIGN KEY ("workspaceId", "engagementId") REFERENCES "Engagement"("workspaceId", "id") ON DELETE RESTRICT ON UPDATE CASCADE;


COMMIT;
